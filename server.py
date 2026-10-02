from fastapi import FastAPI, APIRouter, HTTPException, Depends, status, UploadFile, File
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from pymongo import MongoClient
from pymongo.cursor import Cursor
# Compatibility shim: pymongo Cursor doesn't have .to_list() like motor does
Cursor.to_list = lambda self, n: list(self.limit(n))
import os
import logging
import time
from collections import defaultdict
from pathlib import Path
from pydantic import BaseModel, Field, EmailStr
from typing import List, Optional
import uuid
from datetime import datetime, timedelta
from fastapi import Request
from passlib.context import CryptContext
from jose import JWTError, jwt
import base64
import secrets
import urllib.request
import urllib.error
import json as _json
import html

def esc(s):
    """HTML-escape a value for safe interpolation into email/HTML templates."""
    return html.escape(s or '', quote=True)

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection - lazy connect (Passenger fork-safe)
mongo_url = os.environ['MONGO_URL']
client = MongoClient(mongo_url, connect=False, serverSelectionTimeoutMS=15000)
db = client[os.environ.get('DB_NAME', 'networth_db')]

# ==================== INDEXES ====================
# Idempotent: create_index is a no-op if the index already exists.
# Kept in try/except so a transient DB issue at boot can't take the API down.
def ensure_indexes():
    try:
        # users: unique email + unique id (registration relies on both)
        db.users.create_index([("email", 1)], unique=True)
        db.users.create_index([("id", 1)], unique=True)
        db.users.create_index([("name", 1)])
        db.users.create_index([("created_at", -1)])
        # posts: feed queries by user_id and created_at
        db.posts.create_index([("id", 1)], unique=True)
        db.posts.create_index([("user_id", 1)])
        db.posts.create_index([("created_at", -1)])
        db.posts.create_index([("anonymous", 1)])
        # connections: $or across from_user_id / to_user_id with status
        db.connections.create_index([("id", 1)], unique=True)
        db.connections.create_index([("from_user_id", 1), ("status", 1)])
        db.connections.create_index([("to_user_id", 1), ("status", 1)])
        # messages: conversation lookups + unread counting
        db.messages.create_index([("id", 1)], unique=True)
        db.messages.create_index([("from_user_id", 1), ("to_user_id", 1)])
        db.messages.create_index([("to_user_id", 1), ("from_user_id", 1), ("read", 1)])
        # groups: membership query + unique id
        db.groups.create_index([("id", 1)], unique=True)
        db.groups.create_index([("member_ids", 1)])
        db.group_messages.create_index([("group_id", 1), ("created_at", 1)])
        # events: list by date
        db.events.create_index([("id", 1)], unique=True)
        db.events.create_index([("date", 1)])
        # reports / invite codes
        db.reports.create_index([("id", 1)], unique=True)
        db.reports.create_index([("status", 1)])
        db.invite_codes.create_index([("code", 1)], unique=True)
        # bookmarks: unique user+post, list by user
        db.bookmarks.create_index([("user_id", 1), ("post_id", 1)], unique=True)
        db.bookmarks.create_index([("user_id", 1), ("created_at", -1)])
        # password resets: one record per user, lookup by user
        db.password_resets.create_index([("user_id", 1)], unique=True)
        logger.info("MongoDB indexes ensured")
    except Exception as e:
        logger.warning("Index creation skipped (non-fatal): %s", e)

# ==================== RATE LIMITING ====================
# In-memory, per-key sliding window. Fine for a single-instance free tier;
# replace with Redis-based limiting if the app ever scales horizontally.

class RateLimiter:
    def __init__(self, max_attempts: int = 5, window_seconds: int = 60):
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self._attempts: dict[str, list[float]] = defaultdict(list)

    def allow(self, key: str) -> bool:
        now = time.time()
        cutoff = now - self.window_seconds
        self._attempts[key] = [t for t in self._attempts[key] if t > cutoff]
        if len(self._attempts[key]) >= self.max_attempts:
            return False
        self._attempts[key].append(now)
        return True

auth_limiter = RateLimiter(max_attempts=5, window_seconds=60)

def _client_ip(request: Request) -> str:
    """Best-effort client IP. Render sits behind a proxy, so trust X-Forwarded-For."""
    fwd = request.headers.get("x-forwarded-for")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.client.host if request.client else "unknown"

# ==================== AVATAR SIZE LIMIT ====================
MAX_AVATAR_BASE64 = 4 * 1024 * 1024  # 4MB of base64 (~3MB image). Real compression is a Phase 2 fix.

# ==================== EMAIL (RESEND) ====================
RESEND_API_KEY = os.environ.get('RESEND_API_KEY', '')
FROM_EMAIL = os.environ.get('FROM_EMAIL', 'Peers <onboarding@resend.dev>')
# Sender for membership approval emails (the invite code). Set MEMBERS_EMAIL to
# "Peers Members <members@networth.ro>" on Render once networth.ro is verified in Resend.
MEMBERS_EMAIL = os.environ.get('MEMBERS_EMAIL', FROM_EMAIL)
# Where new-application notifications go. Defaults to the first admin email.
ADMIN_NOTIFY_EMAIL = os.environ.get('ADMIN_NOTIFY_EMAIL', '')
APP_URL = 'https://peers.networth.ro'

def _send_email(to: str, subject: str, html: str, from_email: str = None) -> bool:
    """Send email via Resend API. Silently skips if RESEND_API_KEY is not set."""
    if not RESEND_API_KEY or not to:
        return False
    try:
        data = _json.dumps({"from": from_email or FROM_EMAIL, "to": [to], "subject": subject, "html": html}).encode()
        req = urllib.request.Request(
            "https://api.resend.com/emails",
            data=data,
            headers={"Authorization": f"Bearer {RESEND_API_KEY}", "Content-Type": "application/json", "User-Agent": "peers-networth/1.0"},
            method="POST",
        )
        urllib.request.urlopen(req, timeout=10)
        logger.info("Email sent to %s: %s", to, subject)
        return True
    except Exception as e:
        body = ""
        try:
            if hasattr(e, "read"):
                body = e.read().decode(errors="replace")
        except Exception:
            pass
        logger.warning("Email send failed to %s: %s %s", to, e, body)
        return False

def _notify_connection_request(recipient_id: str, sender_name: str, sender_headline: str):
    """Send email notification for a new connection request (fire-and-forget)."""
    user = db.users.find_one({"id": recipient_id})
    if not user or not user.get("email"):
        return
    name = user.get("name", "").split()[0] or "there"
    _send_email(
        user["email"],
        f"{sender_name} wants to connect on Peers",
        f"""<div style="font-family:-apple-system,sans-serif;max-width:480px;margin:0 auto;padding:20px">
        <h2 style="color:#00BCD4">🤝 New connection request</h2>
        <p>Hi {name},</p>
        <p><b>{esc(sender_name)}</b> ({esc(sender_headline) or 'Peers member'}) wants to connect with you.</p>
        <p style="margin:20px 0"><a href="{APP_URL}/network" style="background:#00BCD4;color:#0D0D0D;padding:12px 24px;border-radius:12px;text-decoration:none;font-weight:700">View request</a></p>
        <p style="color:#888;font-size:12px">— Peers by NetWorth</p></div>"""
    )

def _notify_new_message(recipient_id: str, sender_name: str, preview: str):
    """Send email notification for a new message (fire-and-forget)."""
    user = db.users.find_one({"id": recipient_id})
    if not user or not user.get("email"):
        return
    name = user.get("name", "").split()[0] or "there"
    _send_email(
        user["email"],
        f"New message from {sender_name} on Peers",
        f"""<div style="font-family:-apple-system,sans-serif;max-width:480px;margin:0 auto;padding:20px">
        <h2 style="color:#00BCD4">💬 New message</h2>
        <p>Hi {name},</p>
        <p><b>{esc(sender_name)}</b> sent you a message:</p>
        <blockquote style="background:#1B1B1B;border-left:3px solid #00BCD4;padding:10px 14px;border-radius:8px;color:#ccc;font-size:14px">{esc(preview[:200])}</blockquote>
        <p style="margin:20px 0"><a href="{APP_URL}/messages" style="background:#00BCD4;color:#0D0D0D;padding:12px 24px;border-radius:12px;text-decoration:none;font-weight:700">Reply</a></p>
        <p style="color:#888;font-size:12px">— Peers by NetWorth</p></div>"""
    )

def _validate_avatar(avatar: Optional[str]):
    if avatar and len(avatar) > MAX_AVATAR_BASE64:
        raise HTTPException(status_code=400, detail="Avatar image is too large (max ~3MB)")

# ==================== IMAGE STORAGE (Cloudflare R2, S3-compatible) ====================
# Images arrive from the client as base64 data URIs. When R2 is configured we upload
# them to object storage and keep only the public URL in Mongo (keeps the DB small and
# API responses light). If R2 is not configured we keep the inline base64 (no breakage).
R2_ACCOUNT_ID = os.environ.get("R2_ACCOUNT_ID")
R2_ACCESS_KEY_ID = os.environ.get("R2_ACCESS_KEY_ID")
R2_SECRET_ACCESS_KEY = os.environ.get("R2_SECRET_ACCESS_KEY")
R2_BUCKET = os.environ.get("R2_BUCKET")
R2_PUBLIC_BASE = (os.environ.get("R2_PUBLIC_BASE") or "").rstrip("/")
_r2_client = None
_R2_IMG_EXT = {"image/jpeg": "jpg", "image/jpg": "jpg", "image/png": "png",
               "image/webp": "webp", "image/gif": "gif"}

def _r2_enabled():
    return all([R2_ACCOUNT_ID, R2_ACCESS_KEY_ID, R2_SECRET_ACCESS_KEY, R2_BUCKET, R2_PUBLIC_BASE])

def _get_r2():
    global _r2_client
    if _r2_client is None:
        import boto3
        _r2_client = boto3.client(
            "s3",
            endpoint_url=f"https://{R2_ACCOUNT_ID}.r2.cloudflarestorage.com",
            aws_access_key_id=R2_ACCESS_KEY_ID,
            aws_secret_access_key=R2_SECRET_ACCESS_KEY,
            region_name="auto",
        )
    return _r2_client

def _store_image(value, prefix):
    """If value is a base64 data URI and R2 is configured, upload it and return the public URL.
    Otherwise return value unchanged (already a URL, empty, or R2 not set up yet)."""
    if not value or not isinstance(value, str) or not value.startswith("data:image"):
        return value
    if not _r2_enabled():
        return value
    try:
        header, b64 = value.split(",", 1)
        mime = header.split(";")[0].split(":", 1)[1].strip().lower()
        ext = _R2_IMG_EXT.get(mime, "jpg")
        raw = base64.b64decode(b64)
        key = f"{prefix}/{uuid.uuid4().hex}.{ext}"
        _get_r2().put_object(
            Bucket=R2_BUCKET, Key=key, Body=raw, ContentType=mime,
            CacheControl="public, max-age=31536000, immutable",
        )
        return f"{R2_PUBLIC_BASE}/{key}"
    except Exception as e:
        logging.getLogger("r2").warning(f"R2 upload failed, keeping inline image: {e}")
        return value

# JWT Configuration
SECRET_KEY = os.environ.get('SECRET_KEY')
if not SECRET_KEY:
    raise ValueError("SECRET_KEY environment variable is required")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7  # 7 days

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer()

# Create the main app
app = FastAPI(title="Peers by NetWorth API")
api_router = APIRouter(prefix="/api")

# Admin emails - these users will automatically be admins
ADMIN_EMAILS = ["flaviusblaga@gmail.com"]

# ==================== MODELS ====================

class UserBase(BaseModel):
    email: EmailStr
    name: str
    bio: Optional[str] = ""
    headline: Optional[str] = ""
    location: Optional[str] = ""
    phone: Optional[str] = ""
    skills: List[str] = []
    experience: List[dict] = []
    language: str = "en"  # "en" or "ro"
    avatar: Optional[str] = None  # base64 image
    can_help_with: List[str] = []
    wins: List[dict] = []  # {id, title, problem, action, result}

class UserCreate(UserBase):
    password: str
    invite_code: Optional[str] = None

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class UserUpdate(BaseModel):
    name: Optional[str] = None
    bio: Optional[str] = None
    headline: Optional[str] = None
    location: Optional[str] = None
    phone: Optional[str] = None
    skills: Optional[List[str]] = None
    experience: Optional[List[dict]] = None
    language: Optional[str] = None
    avatar: Optional[str] = None  # base64 image
    can_help_with: Optional[List[str]] = None
    wins: Optional[List[dict]] = None

class UserResponse(UserBase):
    id: str
    created_at: datetime
    connections_count: int = 0
    avatar: Optional[str] = None
    is_admin: bool = False
    is_blocked: bool = False

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserResponse

class PostCreate(BaseModel):
    content: str
    image: Optional[str] = None  # base64
    link: Optional[str] = None
    anonymous: Optional[bool] = False  # dilemma post - author hidden
    category: Optional[str] = None  # e.g. "cariera", "investitii", "business", "dilema", "general"
    tags: Optional[List[str]] = None  # free-form hashtags

class PostUpdate(BaseModel):
    content: Optional[str] = None
    link: Optional[str] = None
    category: Optional[str] = None
    tags: Optional[List[str]] = None

class CommentUpdate(BaseModel):
    content: str

class PostResponse(BaseModel):
    id: str
    user_id: str
    user_name: str
    user_headline: Optional[str] = ""
    user_avatar: Optional[str] = None
    content: str
    image: Optional[str] = None
    link: Optional[str] = None
    category: Optional[str] = None
    tags: Optional[List[str]] = []
    likes: List[str] = []
    comments: List[dict] = []
    created_at: datetime
    bookmarked: Optional[bool] = False  # set when a user's bookmarks are returned
    reported: Optional[bool] = False  # set when the current user has reported this post

class BookmarkResponse(BaseModel):
    id: str
    user_id: str
    post_id: str
    created_at: datetime

class CommentCreate(BaseModel):
    content: str

class ConnectionRequest(BaseModel):
    to_user_id: str

class ConnectionResponse(BaseModel):
    id: str
    from_user_id: str
    from_user_name: str
    from_user_headline: Optional[str] = ""
    from_user_avatar: Optional[str] = None
    to_user_id: str
    to_user_name: str
    to_user_headline: Optional[str] = ""
    to_user_avatar: Optional[str] = None
    status: str  # pending, accepted, rejected
    created_at: datetime

class MessageCreate(BaseModel):
    to_user_id: str
    content: str

class MessageResponse(BaseModel):
    id: str
    from_user_id: str
    from_user_name: str
    to_user_id: str
    to_user_name: str
    content: str
    read: bool = False
    created_at: datetime

class ConversationResponse(BaseModel):
    user_id: str
    user_name: str
    user_headline: Optional[str] = ""
    user_avatar: Optional[str] = None
    last_message: str
    last_message_time: datetime
    unread_count: int = 0

# ==================== GROUP MODELS ====================

class GroupCreate(BaseModel):
    name: str
    member_ids: List[str] = []
    avatar: Optional[str] = None

class GroupUpdate(BaseModel):
    name: Optional[str] = None
    avatar: Optional[str] = None

class GroupMemberInfo(BaseModel):
    id: str
    name: str
    avatar: Optional[str] = None
    headline: Optional[str] = ""

class GroupResponse(BaseModel):
    id: str
    name: str
    avatar: Optional[str] = None
    owner_id: str
    owner_name: str
    members: List[GroupMemberInfo] = []
    member_count: int = 0
    last_message: Optional[str] = None
    last_message_time: Optional[datetime] = None
    unread_count: int = 0
    created_at: datetime

class GroupMessageCreate(BaseModel):
    content: str

class GroupMessageResponse(BaseModel):
    id: str
    group_id: str
    from_user_id: str
    from_user_name: str
    from_user_avatar: Optional[str] = None
    content: str
    created_at: datetime

class GroupMembersAdd(BaseModel):
    user_ids: List[str]

# ==================== ADMIN MODELS ====================

class ReportCreate(BaseModel):
    reported_user_id: Optional[str] = None
    reported_post_id: Optional[str] = None
    reason: str
    description: Optional[str] = ""

class ReportResponse(BaseModel):
    id: str
    reporter_id: str
    reporter_name: str
    reporter_email: Optional[str] = None
    reported_user_id: Optional[str] = None
    reported_user_name: Optional[str] = None
    reported_post_id: Optional[str] = None
    reported_post_content: Optional[str] = None
    reason: str
    description: str
    status: str  # pending, resolved, dismissed
    created_at: datetime

class AdminStats(BaseModel):
    total_users: int
    total_posts: int
    total_connections: int
    total_messages: int
    pending_reports: int
    blocked_users: int
    new_users_today: int
    new_posts_today: int

class AdminUserUpdate(BaseModel):
    is_admin: Optional[bool] = None
    is_blocked: Optional[bool] = None
    new_password: Optional[str] = None  # admin forced password reset

# ==================== HELPERS ====================

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

def create_access_token(data: dict) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        token = credentials.credentials
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise HTTPException(status_code=401, detail="Invalid token")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    user = db.users.find_one({"id": user_id})
    if user is None:
        raise HTTPException(status_code=401, detail="User not found")
    if user.get("is_blocked", False):
        raise HTTPException(status_code=403, detail="Account is blocked")
    return user

def get_admin_user(current_user: dict = Depends(get_current_user)):
    """Verify user is an admin"""
    is_admin = current_user.get("is_admin", False) or current_user.get("email") in ADMIN_EMAILS
    if not is_admin:
        raise HTTPException(status_code=403, detail="Admin access required")
    return current_user

def get_connections_count(user_id: str) -> int:
    count = db.connections.count_documents({
        "$or": [
            {"from_user_id": user_id, "status": "accepted"},
            {"to_user_id": user_id, "status": "accepted"}
        ]
    })
    return count

# ==================== AUTH ROUTES ====================

@api_router.post("/auth/register", response_model=TokenResponse)
def register(user_data: UserCreate, request: Request):
    # Rate limit registration by IP to slow down account-creation spam
    if not auth_limiter.allow(f"register:{_client_ip(request)}"):
        raise HTTPException(status_code=429, detail="Too many registrations. Try again later.")
    _validate_avatar(user_data.avatar)

    # Check if email exists
    existing = db.users.find_one({"email": user_data.email})
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")

    # Invite code required (admins exempt)
    used_code = None
    used_source = ""
    if user_data.email not in ADMIN_EMAILS:
        code = (user_data.invite_code or "").strip().upper()
        if not code:
            raise HTTPException(status_code=403, detail="Invite code required")
        inv = db.invite_codes.find_one({"code": code, "active": True})
        if not inv:
            raise HTTPException(status_code=403, detail="Invalid invite code")
        if inv.get("max_uses") and inv.get("used_count", 0) >= inv["max_uses"]:
            raise HTTPException(status_code=403, detail="Invite code already used up")
        db.invite_codes.update_one(
            {"code": code},
            {"$inc": {"used_count": 1}, "$push": {"used_by": user_data.email}}
        )
        used_code = code
        used_source = inv.get("note", "")
    else:
        used_source = "admin"
    
    # Create user
    user_id = str(uuid.uuid4())
    is_admin = user_data.email in ADMIN_EMAILS
    user_dict = {
        "id": user_id,
        "email": user_data.email,
        "name": user_data.name,
        "password_hash": get_password_hash(user_data.password),
        "bio": user_data.bio or "",
        "headline": user_data.headline or "",
        "location": user_data.location or "",
        "phone": user_data.phone or "",
        "skills": user_data.skills or [],
        "experience": user_data.experience or [],
        "language": user_data.language or "en",
        "is_admin": is_admin,
        "is_blocked": False,
        "can_help_with": [],
        "wins": [],
        "invite_code": used_code,
        "invite_source": used_source,
        "created_at": datetime.utcnow()
    }

    db.users.insert_one(user_dict)
    
    # Create token
    access_token = create_access_token({"sub": user_id})
    
    return TokenResponse(
        access_token=access_token,
        user=UserResponse(
            id=user_id,
            email=user_data.email,
            name=user_data.name,
            bio=user_dict["bio"],
            headline=user_dict["headline"],
            location=user_dict["location"],
            phone=user_dict["phone"],
            skills=user_dict["skills"],
            experience=user_dict["experience"],
            language=user_dict["language"],
            created_at=user_dict["created_at"],
            connections_count=0,
            is_admin=is_admin,
            is_blocked=False
        )
    )

@api_router.post("/auth/login", response_model=TokenResponse)
def login(credentials: UserLogin, request: Request):
    # Rate limit per IP to slow down credential brute-forcing
    if not auth_limiter.allow(f"login:{_client_ip(request)}"):
        raise HTTPException(status_code=429, detail="Too many login attempts. Try again later.")
    user = db.users.find_one({"email": credentials.email})
    if not user or not verify_password(credentials.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    
    access_token = create_access_token({"sub": user["id"]})
    connections_count = get_connections_count(user["id"])
    is_admin = user.get("is_admin", False) or user.get("email") in ADMIN_EMAILS
    
    return TokenResponse(
        access_token=access_token,
        user=UserResponse(
            id=user["id"],
            email=user["email"],
            name=user["name"],
            bio=user.get("bio", ""),
            headline=user.get("headline", ""),
            location=user.get("location", ""),
            phone=user.get("phone", ""),
            skills=user.get("skills", []),
            experience=user.get("experience", []),
            language=user.get("language", "en"),
            created_at=user["created_at"],
            connections_count=connections_count,
            avatar=user.get("avatar"),
            can_help_with=user.get("can_help_with", []),
            wins=user.get("wins", []),
            is_admin=is_admin,
            is_blocked=user.get("is_blocked", False)
        )
    )

# ==================== PASSWORD RESET (EMAIL CODE) ====================
PASSWORD_RESET_CODE_TTL_SECONDS = 10 * 60  # 10 minutes

class ForgotPasswordRequest(BaseModel):
    email: EmailStr

class ResetPasswordRequest(BaseModel):
    email: EmailStr
    code: str
    new_password: str

@api_router.post("/auth/forgot-password")
def forgot_password(req: ForgotPasswordRequest):
    """Send a 6-digit reset code to the user's email (if the account exists)."""
    user = db.users.find_one({"email": req.email})
    if user:
        code = str(secrets.randbelow(1000000)).zfill(6)
        db.password_resets.update_one(
            {"user_id": user["id"]},
            {"$set": {
                "code": code,
                "expires_at": datetime.utcnow() + timedelta(seconds=PASSWORD_RESET_CODE_TTL_SECONDS),
                "used": False,
                "created_at": datetime.utcnow(),
            }},
            upsert=True,
        )
        _send_email(
            user["email"],
            "Your Peers password reset code",
            f"""<div style="font-family:-apple-system,sans-serif;max-width:480px;margin:0 auto;padding:20px">
            <h2 style="color:#00BCD4">🔑 Password reset</h2>
            <p>Hi {esc(user.get('name', '')).split()[0] or 'there'},</p>
            <p>Use this code to reset your Peers password. It expires in 10 minutes.</p>
            <p style="font-size:28px;font-weight:800;letter-spacing:6px;background:#1B1B1B;padding:14px;border-radius:12px;text-align:center">{code}</p>
            <p style="color:#888;font-size:12px">If you didn't request this, you can safely ignore this email.</p>
            <p style="color:#888;font-size:12px">— Peers by NetWorth</p></div>"""
        )
    # Always return 200 so we don't leak which emails are registered
    return {"message": "If that email is registered, a reset code has been sent."}

@api_router.post("/auth/reset-password")
def reset_password(req: ResetPasswordRequest):
    """Verify the emailed code and set a new password."""
    user = db.users.find_one({"email": req.email})
    if not user:
        raise HTTPException(status_code=404, detail="Account not found")
    rec = db.password_resets.find_one({"user_id": user["id"]})
    if not rec or rec.get("used") or rec.get("expires_at") is None:
        raise HTTPException(status_code=400, detail="No active reset code. Request a new one.")
    if rec["expires_at"] < datetime.utcnow():
        raise HTTPException(status_code=400, detail="Code expired. Request a new one.")
    # Compare safely — constant-ish comparison, accept whitespace stripped
    supplied = req.code.strip()
    stored = str(rec.get("code", ""))
    if not secrets.compare_digest(supplied.encode(), stored.encode()):
        raise HTTPException(status_code=400, detail="Invalid code")
    db.users.update_one({"id": user["id"]}, {"$set": {"password_hash": get_password_hash(req.new_password)}})
    db.password_resets.update_one({"user_id": user["id"]}, {"$set": {"used": True}})
    return {"message": "Password updated. You can now log in."}

@api_router.get("/auth/me", response_model=UserResponse)
def get_me(current_user: dict = Depends(get_current_user)):
    connections_count = get_connections_count(current_user["id"])
    is_admin = current_user.get("is_admin", False) or current_user.get("email") in ADMIN_EMAILS
    return UserResponse(
        id=current_user["id"],
        email=current_user["email"],
        name=current_user["name"],
        bio=current_user.get("bio", ""),
        headline=current_user.get("headline", ""),
        location=current_user.get("location", ""),
        phone=current_user.get("phone", ""),
        skills=current_user.get("skills", []),
        experience=current_user.get("experience", []),
        language=current_user.get("language", "en"),
        created_at=current_user["created_at"],
        connections_count=connections_count,
        avatar=current_user.get("avatar"),
        can_help_with=current_user.get("can_help_with", []),
        wins=current_user.get("wins", []),
        is_admin=is_admin,
        is_blocked=current_user.get("is_blocked", False)
    )

@api_router.put("/auth/me", response_model=UserResponse)
def update_me(update_data: UserUpdate, current_user: dict = Depends(get_current_user)):
    _validate_avatar(update_data.avatar)
    update_dict = {k: v for k, v in update_data.dict().items() if v is not None}
    if update_dict.get("avatar"):
        update_dict["avatar"] = _store_image(update_dict["avatar"], "avatars")
    if update_dict:
        db.users.update_one({"id": current_user["id"]}, {"$set": update_dict})
    
    updated_user = db.users.find_one({"id": current_user["id"]})
    connections_count = get_connections_count(current_user["id"])
    is_admin = updated_user.get("is_admin", False) or updated_user.get("email") in ADMIN_EMAILS
    
    return UserResponse(
        id=updated_user["id"],
        email=updated_user["email"],
        name=updated_user["name"],
        bio=updated_user.get("bio", ""),
        headline=updated_user.get("headline", ""),
        location=updated_user.get("location", ""),
        phone=updated_user.get("phone", ""),
        skills=updated_user.get("skills", []),
        experience=updated_user.get("experience", []),
        language=updated_user.get("language", "en"),
        created_at=updated_user["created_at"],
        connections_count=connections_count,
        avatar=updated_user.get("avatar"),
        can_help_with=updated_user.get("can_help_with", []),
        wins=updated_user.get("wins", []),
        is_admin=is_admin,
        is_blocked=updated_user.get("is_blocked", False)
    )

# ==================== GDPR: DATA EXPORT & ACCOUNT DELETION ====================

@api_router.get("/auth/me/export")
def export_my_data(current_user: dict = Depends(get_current_user)):
    """GDPR data portability: return ALL personal data we hold for the current user as JSON.
    Password hash and internal Mongo _id are intentionally excluded."""
    uid = current_user["id"]

    def clean(doc):
        if isinstance(doc, dict):
            doc.pop("_id", None)
            doc.pop("password_hash", None)
        return doc

    profile = clean(dict(current_user))

    posts = [clean(p) for p in db.posts.find({"user_id": uid})]
    bookmarks = [clean(b) for b in db.bookmarks.find({"user_id": uid})]
    connections = [clean(c) for c in db.connections.find(
        {"$or": [{"from_user_id": uid}, {"to_user_id": uid}]})]
    messages = [clean(m) for m in db.messages.find(
        {"$or": [{"from_user_id": uid}, {"to_user_id": uid}]})]
    groups = [clean(g) for g in db.groups.find({"member_ids": uid})]
    events = [clean(e) for e in db.events.find({"rsvps": uid})]
    reports = [clean(r) for r in db.reports.find({"reporter_id": uid})]

    payload = {
        "exported_at": datetime.utcnow().isoformat() + "Z",
        "profile": profile,
        "posts": posts,
        "bookmarks": bookmarks,
        "connections": connections,
        "messages": messages,
        "groups": groups,
        "events_rsvped": events,
        "reports_i_made": reports,
    }
    # JSON-safe (datetime -> isoformat) and force download as a file
    body = _json.dumps(payload, default=str, ensure_ascii=False, indent=2)
    from fastapi.responses import Response
    return Response(
        content=body,
        media_type="application/json",
        headers={"Content-Disposition": 'attachment; filename="peers-datele-mele.json"'},
    )


@api_router.delete("/auth/me")
def delete_my_account(current_user: dict = Depends(get_current_user)):
    """GDPR right to erasure: permanently delete the current user and all their data."""
    uid = current_user["id"]

    db.users.delete_one({"id": uid})
    db.posts.delete_many({"user_id": uid})
    db.connections.delete_many({"$or": [{"from_user_id": uid}, {"to_user_id": uid}]})
    db.messages.delete_many({"$or": [{"from_user_id": uid}, {"to_user_id": uid}]})
    db.bookmarks.delete_many({"user_id": uid})
    db.board.delete_many({"user_id": uid})
    db.intros.delete_many({"$or": [{"requester_id": uid}, {"via_id": uid}, {"target_id": uid}]})
    db.slots.delete_many({"$or": [{"host_id": uid}, {"booked_by_id": uid}]})
    db.endorsements.delete_many({"$or": [{"user_id": uid}, {"endorser_id": uid}]})
    db.resources.delete_many({"user_id": uid})
    db.jobs.delete_many({"user_id": uid})
    db.reports.delete_many({"reporter_id": uid})
    db.password_resets.delete_many({"user_id": uid})
    # Remove the user from any group memberships and event RSVPs (shared docs kept)
    db.groups.update_many({"member_ids": uid}, {"$pull": {"member_ids": uid}})
    db.events.update_many({"rsvps": uid}, {"$pull": {"rsvps": uid}})

    return {"message": "Account and all associated data permanently deleted"}


# ==================== IMAGE UPLOAD (multipart -> R2) ====================
@api_router.post("/upload")
async def upload_image(file: UploadFile = File(...), current_user: dict = Depends(get_current_user)):
    """Upload an image as a real file. Stores it in R2 and returns its public URL.
    If R2 isn't configured yet, returns a base64 data URI so the app still works."""
    raw = await file.read()
    if len(raw) > 6 * 1024 * 1024:
        raise HTTPException(status_code=400, detail="Image too large (max 6MB)")
    ct = (file.content_type or "image/jpeg").lower()
    ext = _R2_IMG_EXT.get(ct, "jpg")
    if _r2_enabled():
        try:
            key = f"uploads/{uuid.uuid4().hex}.{ext}"
            _get_r2().put_object(Bucket=R2_BUCKET, Key=key, Body=raw, ContentType=ct,
                                 CacheControl="public, max-age=31536000, immutable")
            return {"url": f"{R2_PUBLIC_BASE}/{key}"}
        except Exception as e:
            logging.getLogger("r2").warning(f"upload failed, falling back to data URI: {e}")
    return {"url": f"data:{ct};base64," + base64.b64encode(raw).decode()}


@api_router.post("/upload-doc")
async def upload_doc(file: UploadFile = File(...), current_user: dict = Depends(get_current_user)):
    """Upload a PDF document (e.g. a job description / announcement). Stores it in R2 and
    returns its public URL + original filename. Falls back to a base64 data URI if R2 isn't set up."""
    raw = await file.read()
    if len(raw) > 10 * 1024 * 1024:
        raise HTTPException(status_code=400, detail="File too large (max 10MB)")
    ct = (file.content_type or "").lower()
    if ct != "application/pdf" and not (file.filename or "").lower().endswith(".pdf"):
        raise HTTPException(status_code=400, detail="Only PDF files are allowed")
    ct = "application/pdf"
    name = (file.filename or "document.pdf")[:160]
    if _r2_enabled():
        try:
            key = f"docs/{uuid.uuid4().hex}.pdf"
            _get_r2().put_object(Bucket=R2_BUCKET, Key=key, Body=raw, ContentType=ct,
                                 CacheControl="public, max-age=31536000, immutable")
            return {"url": f"{R2_PUBLIC_BASE}/{key}", "name": name}
        except Exception as e:
            logging.getLogger("r2").warning(f"doc upload failed, falling back to data URI: {e}")
    return {"url": f"data:{ct};base64," + base64.b64encode(raw).decode(), "name": name}


# ==================== NEWS / MARKET DATA ====================
_fx_cache = {"ts": 0.0, "data": None}
FX_CURRENCIES = ["EUR", "USD", "GBP", "CHF"]
_FX_UA = "Mozilla/5.0 (compatible; PeersApp/1.0; +https://peers.networth.ro)"

def _fx_fetch_json(url):
    req = urllib.request.Request(url, headers={"User-Agent": _FX_UA, "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=10) as r:
        return _json.loads(r.read().decode("utf-8"))

@api_router.get("/fx")
def get_fx():
    """RON reference rates (ECB via Frankfurter, fallback er-api), cached ~3h.
    rate = RON per 1 unit of the currency."""
    now = time.time()
    if _fx_cache["data"] and now - _fx_cache["ts"] < 3 * 3600:
        return _fx_cache["data"]
    data = None
    # Primary: Frankfurter (ECB reference rates)
    try:
        d = _fx_fetch_json("https://api.frankfurter.app/latest?base=RON&symbols=EUR,USD,GBP,CHF")
        rates = {c: round(1.0 / v, 4) for c, v in d.get("rates", {}).items() if v}
        if rates:
            data = {"base": "RON", "date": d.get("date"), "rates": rates, "source": "BCE"}
    except Exception as e:
        logging.getLogger("fx").warning(f"frankfurter failed: {e}")
    # Fallback: open.er-api.com
    if not data:
        try:
            d = _fx_fetch_json("https://open.er-api.com/v6/latest/RON")
            r = d.get("rates", {})
            rates = {c: round(1.0 / r[c], 4) for c in FX_CURRENCIES if r.get(c)}
            if rates:
                date = (d.get("time_last_update_utc") or "")[:16]
                data = {"base": "RON", "date": date, "rates": rates, "source": "exchangerate-api"}
        except Exception as e:
            logging.getLogger("fx").warning(f"er-api failed: {e}")
    if data:
        _fx_cache["data"] = data
        _fx_cache["ts"] = now
        return data
    if _fx_cache["data"]:
        return _fx_cache["data"]
    raise HTTPException(status_code=503, detail="FX data temporarily unavailable")


_crypto_cache = {"ts": 0.0, "data": None}

@api_router.get("/crypto")
def get_crypto():
    """BTC / ETH / XRP prices in USD with 24h change, cached ~10 min."""
    now = time.time()
    if _crypto_cache["data"] and now - _crypto_cache["ts"] < 600:
        return _crypto_cache["data"]
    try:
        d = _fx_fetch_json("https://api.coingecko.com/api/v3/simple/price?ids=bitcoin,ethereum,ripple&vs_currencies=usd&include_24hr_change=true")
        m = {"bitcoin": "BTC", "ethereum": "ETH", "ripple": "XRP"}
        order = {"BTC": 0, "ETH": 1, "XRP": 2}
        coins = [{"symbol": m[k], "usd": round(v["usd"], 2), "change24h": round(v.get("usd_24h_change", 0.0) or 0.0, 2)}
                 for k, v in d.items() if k in m]
        coins.sort(key=lambda c: order.get(c["symbol"], 9))
        data = {"coins": coins}
        _crypto_cache["data"] = data
        _crypto_cache["ts"] = now
        return data
    except Exception as e:
        logging.getLogger("crypto").warning(f"coingecko failed: {e}")
        if _crypto_cache["data"]:
            return _crypto_cache["data"]
        raise HTTPException(status_code=503, detail="Crypto data unavailable")


_bet_cache = {"ts": 0.0, "data": None}

@api_router.get("/bet")
def get_bet():
    """BET index (Bucharest) from stocks.networth.ro, cached ~15 min."""
    import re
    now = time.time()
    if _bet_cache["data"] and now - _bet_cache["ts"] < 900:
        return _bet_cache["data"]
    try:
        d = _fx_fetch_json("https://stocks.networth.ro/api/analysis.php")
        summary = d.get("summary", "") or ""
        m = re.search(r"BET\s*([+-]?[\d.,]+)\s*%\s*\(([\d.,]+)", summary)
        data = {
            "index": "BET",
            "change": m.group(1) if m else None,   # e.g. "-1,60"
            "value": m.group(2) if m else None,    # e.g. "30.521,03"
            "date": d.get("snapshotDate") or d.get("date"),
            "source": "stocks.networth.ro",
        }
        if data["value"]:
            _bet_cache["data"] = data
            _bet_cache["ts"] = now
        return data
    except Exception as e:
        logging.getLogger("bet").warning(f"BET fetch failed: {e}")
        if _bet_cache["data"]:
            return _bet_cache["data"]
        raise HTTPException(status_code=503, detail="BET data unavailable")


import xml.etree.ElementTree as _ET
_news_cache = {"ts": 0.0, "data": None}

@api_router.get("/news")
def get_news():
    """Curated news feed for the community — Romanian business/economy headlines, cached ~30 min."""
    now = time.time()
    if _news_cache["data"] and now - _news_cache["ts"] < 1800:
        return _news_cache["data"]
    try:
        url = "https://news.google.com/rss/search?q=(economie%20OR%20business%20OR%20bursa)%20Romania%20when:7d&hl=ro&gl=RO&ceid=RO:ro"
        req = urllib.request.Request(url, headers={"User-Agent": _FX_UA})
        xml = urllib.request.urlopen(req, timeout=12).read().decode("utf-8")
        root = _ET.fromstring(xml)
        items = []
        for it in root.findall(".//item")[:14]:
            title = (it.findtext("title") or "").strip()
            link = (it.findtext("link") or "").strip()
            pub = (it.findtext("pubDate") or "").strip()
            src_el = it.find("source")
            source = (src_el.text or "").strip() if src_el is not None else ""
            if source and title.endswith(" - " + source):
                title = title[: -(len(source) + 3)]
            items.append({"title": title, "link": link, "published": pub, "source": source})
        data = {"items": items}
        _news_cache["data"] = data
        _news_cache["ts"] = now
        return data
    except Exception as e:
        logging.getLogger("news").warning(f"news feed failed: {e}")
        if _news_cache["data"]:
            return _news_cache["data"]
        raise HTTPException(status_code=503, detail="News unavailable")


# ==================== ASK & OFFER BOARD ====================
class BoardCreate(BaseModel):
    type: str  # 'ask' | 'offer'
    title: str
    description: Optional[str] = ""
    tags: Optional[List[str]] = None

@api_router.post("/board")
def create_board(data: BoardCreate, current_user: dict = Depends(get_current_user)):
    if data.type not in ("ask", "offer"):
        raise HTTPException(status_code=400, detail="Invalid type")
    title = (data.title or "").strip()
    if not title:
        raise HTTPException(status_code=400, detail="Title is required")
    doc = {
        "id": str(uuid.uuid4()),
        "user_id": current_user["id"],
        "user_name": current_user["name"],
        "user_headline": current_user.get("headline", ""),
        "user_avatar": current_user.get("avatar"),
        "type": data.type,
        "title": title[:160],
        "description": (data.description or "").strip()[:2000],
        "tags": data.tags or [],
        "status": "open",
        "created_at": datetime.utcnow(),
    }
    db.board.insert_one(doc)
    doc.pop("_id", None)
    return doc

@api_router.get("/board")
def list_board(type: Optional[str] = None, current_user: dict = Depends(get_current_user)):
    q = {"status": "open"}
    if type in ("ask", "offer"):
        q["type"] = type
    return list(db.board.find(q, {"_id": 0}).sort("created_at", -1).limit(100))

@api_router.post("/board/{item_id}/close")
def close_board(item_id: str, current_user: dict = Depends(get_current_user)):
    it = db.board.find_one({"id": item_id})
    if not it:
        raise HTTPException(status_code=404, detail="Not found")
    if it["user_id"] != current_user["id"]:
        raise HTTPException(status_code=403, detail="Not allowed")
    db.board.update_one({"id": item_id}, {"$set": {"status": "closed"}})
    return {"message": "closed"}

@api_router.delete("/board/{item_id}")
def delete_board(item_id: str, current_user: dict = Depends(get_current_user)):
    it = db.board.find_one({"id": item_id})
    if not it:
        raise HTTPException(status_code=404, detail="Not found")
    is_admin = current_user.get("is_admin") or current_user.get("email") in ADMIN_EMAILS
    if it["user_id"] != current_user["id"] and not is_admin:
        raise HTTPException(status_code=403, detail="Not allowed")
    db.board.delete_one({"id": item_id})
    return {"message": "deleted"}


# ==================== RESOURCE LIBRARY ====================
class ResourceCreate(BaseModel):
    title: str
    url: str
    description: Optional[str] = ""
    category: Optional[str] = ""

@api_router.post("/resources")
def create_resource(data: ResourceCreate, current_user: dict = Depends(get_current_user)):
    title = (data.title or "").strip()
    url = (data.url or "").strip()
    if not title or not url:
        raise HTTPException(status_code=400, detail="Title and link are required")
    if not url.startswith("http"):
        url = "https://" + url
    doc = {
        "id": str(uuid.uuid4()),
        "user_id": current_user["id"], "user_name": current_user["name"],
        "title": title[:160], "url": url[:500], "description": (data.description or "").strip()[:1000],
        "category": (data.category or "").strip()[:60], "created_at": datetime.utcnow(),
    }
    db.resources.insert_one(doc)
    doc.pop("_id", None)
    return doc

@api_router.get("/resources")
def list_resources(current_user: dict = Depends(get_current_user)):
    return list(db.resources.find({}, {"_id": 0}).sort("created_at", -1).limit(200))

@api_router.delete("/resources/{res_id}")
def delete_resource(res_id: str, current_user: dict = Depends(get_current_user)):
    r = db.resources.find_one({"id": res_id})
    if not r:
        raise HTTPException(status_code=404, detail="Not found")
    is_admin = current_user.get("is_admin") or current_user.get("email") in ADMIN_EMAILS
    if r["user_id"] != current_user["id"] and not is_admin:
        raise HTTPException(status_code=403, detail="Not allowed")
    db.resources.delete_one({"id": res_id})
    return {"message": "deleted"}


# ==================== JOB / OPPORTUNITY BOARD ====================
class JobCreate(BaseModel):
    title: str
    kind: Optional[str] = "role"          # role | board | advisory | collab
    company: Optional[str] = ""
    location: Optional[str] = ""
    description: Optional[str] = ""
    contact: Optional[str] = ""           # email or URL to reach out / refer
    doc_url: Optional[str] = ""           # attached PDF (job description / announcement)
    doc_name: Optional[str] = ""

@api_router.post("/jobs")
def create_job(data: JobCreate, current_user: dict = Depends(get_current_user)):
    title = (data.title or "").strip()
    if not title:
        raise HTTPException(status_code=400, detail="Title is required")
    kind = (data.kind or "role").strip().lower()
    if kind not in ("role", "board", "advisory", "collab"):
        kind = "role"
    doc = {
        "id": str(uuid.uuid4()),
        "user_id": current_user["id"], "user_name": current_user["name"],
        "title": title[:160], "kind": kind,
        "company": (data.company or "").strip()[:120],
        "location": (data.location or "").strip()[:120],
        "description": (data.description or "").strip()[:2000],
        "contact": (data.contact or "").strip()[:300],
        "doc_url": (data.doc_url or "").strip(),
        "doc_name": (data.doc_name or "").strip()[:160],
        "open": True, "created_at": datetime.utcnow(),
    }
    db.jobs.insert_one(doc)
    doc.pop("_id", None)
    return doc

@api_router.get("/jobs")
def list_jobs(kind: Optional[str] = None, current_user: dict = Depends(get_current_user)):
    q = {"open": True}
    if kind and kind != "all":
        q["kind"] = kind
    return list(db.jobs.find(q, {"_id": 0}).sort("created_at", -1).limit(200))

@api_router.post("/jobs/{job_id}/close")
def close_job(job_id: str, current_user: dict = Depends(get_current_user)):
    j = db.jobs.find_one({"id": job_id})
    if not j:
        raise HTTPException(status_code=404, detail="Not found")
    is_admin = current_user.get("is_admin") or current_user.get("email") in ADMIN_EMAILS
    if j["user_id"] != current_user["id"] and not is_admin:
        raise HTTPException(status_code=403, detail="Not allowed")
    db.jobs.update_one({"id": job_id}, {"$set": {"open": False}})
    return {"message": "closed"}

@api_router.delete("/jobs/{job_id}")
def delete_job(job_id: str, current_user: dict = Depends(get_current_user)):
    j = db.jobs.find_one({"id": job_id})
    if not j:
        raise HTTPException(status_code=404, detail="Not found")
    is_admin = current_user.get("is_admin") or current_user.get("email") in ADMIN_EMAILS
    if j["user_id"] != current_user["id"] and not is_admin:
        raise HTTPException(status_code=403, detail="Not allowed")
    db.jobs.delete_one({"id": job_id})
    return {"message": "deleted"}


# ==================== MEMBERSHIP APPLICATIONS (mini-interview) ====================
class ApplicationCreate(BaseModel):
    name: str
    email: EmailStr
    phone: Optional[str] = ""
    position: str
    experience: Optional[str] = ""          # e.g. "5-10" (years range)
    interests: Optional[List[str]] = []     # multi-select expectations
    note: Optional[str] = ""                # optional free text

@api_router.post("/applications")
def create_application(data: ApplicationCreate, request: Request):
    """PUBLIC endpoint — a candidate submits a short membership application.
    Lands in the admin zone; admin reviews, then approves to issue an invite code."""
    if not auth_limiter.allow(f"apply:{_client_ip(request)}"):
        raise HTTPException(status_code=429, detail="Too many submissions. Try again later.")
    name = (data.name or "").strip()
    position = (data.position or "").strip()
    email = (data.email or "").strip().lower()
    if not name or not position:
        raise HTTPException(status_code=400, detail="Name and current position are required")
    # Already a member? Still accept the application, admin will see it; but flag duplicates.
    already_member = db.users.find_one({"email": email}) is not None
    pending = db.applications.find_one({"email": email, "status": "pending"})
    if pending:
        raise HTTPException(status_code=400, detail="You already have a pending application. We'll be in touch.")
    doc = {
        "id": str(uuid.uuid4()),
        "name": name[:120], "email": email[:160], "phone": (data.phone or "").strip()[:40],
        "position": position[:160], "experience": (data.experience or "").strip()[:40],
        "interests": [str(x).strip()[:60] for x in (data.interests or [])][:10],
        "note": (data.note or "").strip()[:1000],
        "status": "pending", "already_member": already_member,
        "created_at": datetime.utcnow(),
    }
    db.applications.insert_one(doc)
    # Notify admin (fire-and-forget)
    try:
        to = ADMIN_NOTIFY_EMAIL or (ADMIN_EMAILS[0] if ADMIN_EMAILS else "")
        if to:
            ints = ", ".join(doc["interests"]) or "—"
            _send_email(
                to, f"New Peers membership application: {esc(name)}",
                f"""<div style="font-family:-apple-system,sans-serif;max-width:520px;margin:0 auto;padding:20px">
                <h2 style="color:#00BCD4">New membership application</h2>
                <p><b>{esc(name)}</b>{' (already a member!)' if already_member else ''}</p>
                <table style="font-size:14px;color:#333">
                <tr><td style="color:#888;padding:2px 10px 2px 0">Email</td><td>{esc(email)}</td></tr>
                <tr><td style="color:#888;padding:2px 10px 2px 0">Phone</td><td>{esc(doc['phone']) or '—'}</td></tr>
                <tr><td style="color:#888;padding:2px 10px 2px 0">Position</td><td>{esc(doc['position'])}</td></tr>
                <tr><td style="color:#888;padding:2px 10px 2px 0">Experience</td><td>{esc(doc['experience']) or '—'} yrs</td></tr>
                <tr><td style="color:#888;padding:2px 10px 2px 0">Interests</td><td>{esc(ints)}</td></tr>
                </table>
                {f'<p style="font-size:14px;color:#333"><b>Note:</b> {esc(doc["note"])}</p>' if doc['note'] else ''}
                <p style="margin:18px 0"><a href="{APP_URL}/admin" style="background:#00BCD4;color:#0D0D0D;padding:12px 24px;border-radius:12px;text-decoration:none;font-weight:700">Review in admin</a></p>
                <p style="color:#888;font-size:12px">— Peers by NetWorth</p></div>""",
            )
    except Exception as e:
        logging.getLogger("applications").warning(f"admin notify failed: {e}")
    return {"message": "Application received. We'll review it and get back to you by email."}

@api_router.get("/admin/applications")
def list_applications(status: Optional[str] = None, admin_user: dict = Depends(get_admin_user)):
    q = {}
    if status and status != "all":
        q["status"] = status
    return list(db.applications.find(q, {"_id": 0}).sort("created_at", -1).limit(300))

@api_router.post("/admin/applications/{app_id}/approve")
def approve_application(app_id: str, admin_user: dict = Depends(get_admin_user)):
    a = db.applications.find_one({"id": app_id})
    if not a:
        raise HTTPException(status_code=404, detail="Application not found")
    if a.get("status") == "approved" and a.get("invite_code"):
        return {"code": a["invite_code"], "message": "Already approved", "emailed": False}
    # Generate a single-use invite code tied to this application
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    code = "".join(secrets.choice(alphabet) for _ in range(8))
    db.invite_codes.insert_one({
        "code": code, "active": True, "max_uses": 1, "used_count": 0, "used_by": [],
        "note": f"application:{a['email']}", "created_by": admin_user["email"],
        "created_at": datetime.utcnow(),
    })
    db.applications.update_one({"id": app_id}, {"$set": {
        "status": "approved", "invite_code": code,
        "approved_by": admin_user["email"], "approved_at": datetime.utcnow(),
    }})
    first = (a.get("name", "").split() or ["there"])[0]
    emailed = _send_email(
        a["email"], "You're invited to Peers by NetWorth",
        f"""<div style="font-family:-apple-system,sans-serif;max-width:480px;margin:0 auto;padding:20px">
        <h2 style="color:#00BCD4">Welcome to Peers</h2>
        <p>Hi {esc(first)},</p>
        <p>Your membership application has been approved. Use the invite code below to create your account:</p>
        <p style="font-size:26px;font-weight:800;letter-spacing:3px;background:#f3f3f3;padding:14px;border-radius:12px;text-align:center;color:#0D0D0D">{code}</p>
        <p style="margin:20px 0"><a href="{APP_URL}/register" style="background:#00BCD4;color:#0D0D0D;padding:12px 24px;border-radius:12px;text-decoration:none;font-weight:700">Create your account</a></p>
        <p style="color:#888;font-size:12px">This code is for you and can be used once. — Peers by NetWorth</p></div>""",
        from_email=MEMBERS_EMAIL,
    )
    return {"code": code, "emailed": emailed}

@api_router.post("/admin/applications/{app_id}/reject")
def reject_application(app_id: str, admin_user: dict = Depends(get_admin_user)):
    r = db.applications.update_one({"id": app_id}, {"$set": {
        "status": "rejected", "reviewed_by": admin_user["email"], "reviewed_at": datetime.utcnow(),
    }})
    if r.matched_count == 0:
        raise HTTPException(status_code=404, detail="Application not found")
    return {"message": "rejected"}

@api_router.delete("/admin/applications/{app_id}")
def delete_application(app_id: str, admin_user: dict = Depends(get_admin_user)):
    r = db.applications.delete_one({"id": app_id})
    if r.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Application not found")
    return {"message": "deleted"}


# ==================== OFFICE HOURS / 1:1 BOOKING ====================
class SlotCreate(BaseModel):
    start: str           # "YYYY-MM-DD HH:MM"
    duration_min: Optional[int] = 30
    topic: Optional[str] = ""

@api_router.post("/slots")
def create_slot(data: SlotCreate, current_user: dict = Depends(get_current_user)):
    start = (data.start or "").strip()
    if not start:
        raise HTTPException(status_code=400, detail="Start time is required")
    doc = {
        "id": str(uuid.uuid4()),
        "host_id": current_user["id"], "host_name": current_user["name"], "host_avatar": current_user.get("avatar"),
        "start": start, "duration_min": int(data.duration_min or 30), "topic": (data.topic or "").strip()[:160],
        "status": "open", "booked_by_id": None, "booked_by_name": None,
        "created_at": datetime.utcnow(),
    }
    db.slots.insert_one(doc)
    doc.pop("_id", None)
    return doc

@api_router.get("/slots")
def list_slots(mine: Optional[int] = 0, current_user: dict = Depends(get_current_user)):
    today = datetime.utcnow().strftime("%Y-%m-%d %H:%M")
    if mine:
        items = list(db.slots.find({"host_id": current_user["id"]}, {"_id": 0}).sort("start", 1).limit(100))
    else:
        items = [s for s in db.slots.find({"status": "open"}, {"_id": 0}).sort("start", 1).limit(200)
                 if s.get("host_id") != current_user["id"] and (s.get("start") or "") >= today][:100]
    return items

@api_router.post("/slots/{slot_id}/book")
def book_slot(slot_id: str, current_user: dict = Depends(get_current_user)):
    s = db.slots.find_one({"id": slot_id})
    if not s:
        raise HTTPException(status_code=404, detail="Not found")
    if s["status"] != "open":
        raise HTTPException(status_code=400, detail="Slot no longer available")
    if s["host_id"] == current_user["id"]:
        raise HTTPException(status_code=400, detail="Can't book your own slot")
    db.slots.update_one({"id": slot_id}, {"$set": {"status": "booked", "booked_by_id": current_user["id"], "booked_by_name": current_user["name"]}})
    _dm(current_user["id"], current_user["name"], s["host_id"], s["host_name"],
        f"Ți-am rezervat slotul de {s['duration_min']} min din {s['start']}. {s.get('topic','')}".strip())
    _dm(s["host_id"], s["host_name"], current_user["id"], current_user["name"],
        f"Rezervare confirmată: {s['start']} ({s['duration_min']} min). Ne auzim atunci.")
    return {"message": "booked"}

@api_router.delete("/slots/{slot_id}")
def delete_slot(slot_id: str, current_user: dict = Depends(get_current_user)):
    s = db.slots.find_one({"id": slot_id})
    if not s:
        raise HTTPException(status_code=404, detail="Not found")
    if s["host_id"] != current_user["id"]:
        raise HTTPException(status_code=403, detail="Not allowed")
    db.slots.delete_one({"id": slot_id})
    return {"message": "deleted"}


# ==================== WARM INTRODUCTIONS ====================
class IntroCreate(BaseModel):
    target_id: str
    via_id: str
    message: Optional[str] = ""

def _accepted_conn_ids(uid: str) -> set:
    ids = set()
    for c in db.connections.find({"status": "accepted", "$or": [{"from_user_id": uid}, {"to_user_id": uid}]}):
        ids.add(c["to_user_id"] if c["from_user_id"] == uid else c["from_user_id"])
    return ids

def _dm(from_id, from_name, to_id, to_name, content):
    db.messages.insert_one({
        "id": str(uuid.uuid4()), "from_user_id": from_id, "from_user_name": from_name,
        "to_user_id": to_id, "to_user_name": to_name, "content": content,
        "read": False, "created_at": datetime.utcnow(),
    })

@api_router.get("/intros/mutuals/{target_id}")
def intro_mutuals(target_id: str, current_user: dict = Depends(get_current_user)):
    """People connected to BOTH me and the target — who could introduce us."""
    mutual = _accepted_conn_ids(current_user["id"]) & _accepted_conn_ids(target_id)
    mutual.discard(current_user["id"]); mutual.discard(target_id)
    return list(db.users.find({"id": {"$in": list(mutual)}}, {"id": 1, "name": 1, "avatar": 1, "headline": 1, "_id": 0}))

@api_router.post("/intros")
def create_intro(data: IntroCreate, current_user: dict = Depends(get_current_user)):
    if data.target_id == current_user["id"] or data.via_id == current_user["id"]:
        raise HTTPException(status_code=400, detail="Invalid request")
    via = db.users.find_one({"id": data.via_id})
    target = db.users.find_one({"id": data.target_id})
    if not via or not target:
        raise HTTPException(status_code=404, detail="User not found")
    # via must be mutual
    if data.via_id not in (_accepted_conn_ids(current_user["id"]) & _accepted_conn_ids(data.target_id)):
        raise HTTPException(status_code=403, detail="That person can't introduce you")
    doc = {
        "id": str(uuid.uuid4()),
        "requester_id": current_user["id"], "requester_name": current_user["name"],
        "via_id": data.via_id, "via_name": via["name"],
        "target_id": data.target_id, "target_name": target["name"],
        "message": (data.message or "").strip()[:500], "status": "pending",
        "created_at": datetime.utcnow(),
    }
    db.intros.insert_one(doc)
    _dm(current_user["id"], current_user["name"], data.via_id, via["name"],
        f"[Cerere de intro] Mă poți prezenta lui {target['name']}? {doc['message']}".strip())
    doc.pop("_id", None)
    return doc

@api_router.get("/intros/incoming")
def intros_incoming(current_user: dict = Depends(get_current_user)):
    return list(db.intros.find({"via_id": current_user["id"], "status": "pending"}, {"_id": 0}).sort("created_at", -1).limit(100))

@api_router.post("/intros/{intro_id}/accept")
def accept_intro(intro_id: str, current_user: dict = Depends(get_current_user)):
    it = db.intros.find_one({"id": intro_id})
    if not it:
        raise HTTPException(status_code=404, detail="Not found")
    if it["via_id"] != current_user["id"]:
        raise HTTPException(status_code=403, detail="Not allowed")
    db.intros.update_one({"id": intro_id}, {"$set": {"status": "accepted"}})
    # Introduce the two sides via DM from the connector
    _dm(current_user["id"], current_user["name"], it["requester_id"], it["requester_name"],
        f"Te-am conectat cu {it['target_name']}. Puteți vorbi direct acum.")
    _dm(current_user["id"], current_user["name"], it["target_id"], it["target_name"],
        f"Ți-l prezint pe {it['requester_name']}. Cred că merită să vorbiți. {it.get('message','')}".strip())
    return {"message": "accepted"}

@api_router.post("/intros/{intro_id}/decline")
def decline_intro(intro_id: str, current_user: dict = Depends(get_current_user)):
    it = db.intros.find_one({"id": intro_id})
    if not it:
        raise HTTPException(status_code=404, detail="Not found")
    if it["via_id"] != current_user["id"]:
        raise HTTPException(status_code=403, detail="Not allowed")
    db.intros.update_one({"id": intro_id}, {"$set": {"status": "declined"}})
    return {"message": "declined"}


# ==================== USER ROUTES ====================

@api_router.get("/users", response_model=List[UserResponse])
def get_users(search: Optional[str] = None, current_user: dict = Depends(get_current_user)):
    query = {"id": {"$ne": current_user["id"]}, "is_blocked": {"$ne": True}}
    if search:
        query["$or"] = [
            {"name": {"$regex": search, "$options": "i"}},
            {"headline": {"$regex": search, "$options": "i"}},
            {"skills": {"$elemMatch": {"$regex": search, "$options": "i"}}},
            {"can_help_with": {"$elemMatch": {"$regex": search, "$options": "i"}}}
        ]
    
    users = list(db.users.find(query).limit(100))
    result = []
    for user in users:
        connections_count = get_connections_count(user["id"])
        is_admin = user.get("is_admin", False) or user.get("email") in ADMIN_EMAILS
        result.append(UserResponse(
            id=user["id"],
            email=user["email"],
            name=user["name"],
            bio=user.get("bio", ""),
            headline=user.get("headline", ""),
            location=user.get("location", ""),
            phone=user.get("phone", ""),
            skills=user.get("skills", []),
            can_help_with=user.get("can_help_with", []),
            experience=user.get("experience", []),
            language=user.get("language", "en"),
            created_at=user["created_at"],
            connections_count=connections_count,
            avatar=user.get("avatar")
        ))
    return result

@api_router.get("/users/{user_id}", response_model=UserResponse)
def get_user(user_id: str, current_user: dict = Depends(get_current_user)):
    user = db.users.find_one({"id": user_id})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    connections_count = get_connections_count(user["id"])
    return UserResponse(
        id=user["id"],
        email=user["email"],
        name=user["name"],
        bio=user.get("bio", ""),
        headline=user.get("headline", ""),
        location=user.get("location", ""),
            phone=user.get("phone", ""),
        skills=user.get("skills", []),
        experience=user.get("experience", []),
        language=user.get("language", "en"),
        created_at=user["created_at"],
        connections_count=connections_count,
        avatar=user.get("avatar"),
        can_help_with=user.get("can_help_with", []),
        wins=user.get("wins", [])
    )

class EndorseBody(BaseModel):
    skill: str

@api_router.post("/users/{user_id}/endorse")
def endorse_user(user_id: str, body: EndorseBody, current_user: dict = Depends(get_current_user)):
    if user_id == current_user["id"]:
        raise HTTPException(status_code=400, detail="You can't endorse yourself")
    skill = (body.skill or "").strip()[:60]
    if not skill:
        raise HTTPException(status_code=400, detail="Skill required")
    existing = db.endorsements.find_one({"user_id": user_id, "endorser_id": current_user["id"], "skill": skill})
    if existing:
        db.endorsements.delete_one({"_id": existing["_id"]})
        return {"endorsed": False}
    db.endorsements.insert_one({
        "id": str(uuid.uuid4()), "user_id": user_id, "endorser_id": current_user["id"],
        "skill": skill, "created_at": datetime.utcnow(),
    })
    return {"endorsed": True}

@api_router.get("/users/{user_id}/endorsements")
def get_endorsements(user_id: str, current_user: dict = Depends(get_current_user)):
    counts: dict = {}
    mine: list = []
    for e in db.endorsements.find({"user_id": user_id}):
        counts[e["skill"]] = counts.get(e["skill"], 0) + 1
        if e["endorser_id"] == current_user["id"]:
            mine.append(e["skill"])
    return {"counts": counts, "mine": mine}

# ==================== POST ROUTES ====================

@api_router.post("/posts", response_model=PostResponse)
def create_post(post_data: PostCreate, current_user: dict = Depends(get_current_user)):
    post_id = str(uuid.uuid4())
    post_dict = {
        "id": post_id,
        "user_id": current_user["id"],
        "user_name": current_user["name"],
        "user_headline": current_user.get("headline", ""),
        "content": post_data.content,
        "image": _store_image(post_data.image, "posts"),
        "link": post_data.link,
        "anonymous": bool(post_data.anonymous),
        "category": post_data.category,
        "tags": post_data.tags or [],
        "likes": [],
        "comments": [],
        "created_at": datetime.utcnow()
    }
    db.posts.insert_one(post_dict)
    return _enrich_post(post_dict)


def _enrich_post(post: dict) -> PostResponse:
    """Attach current user avatar (and comment authors' avatars) fetched from users collection."""
    if post.get("anonymous"):
        # Dilemma post: mask the author entirely
        post["user_id"] = ""
        post["user_name"] = "🎭 Anonymous member"
        post["user_headline"] = "Dilemma / Dilemă"
        post["user_avatar"] = None
    else:
        user_avatar = None
        author = db.users.find_one({"id": post.get("user_id")}, {"avatar": 1, "headline": 1, "name": 1})
        if author:
            user_avatar = author.get("avatar")
            # Also refresh headline & name (may have changed)
            post["user_headline"] = author.get("headline", post.get("user_headline", ""))
            post["user_name"] = author.get("name", post.get("user_name", ""))
        post["user_avatar"] = user_avatar

    # Enrich comments with authors' avatars
    comments = post.get("comments", []) or []
    if comments:
        author_ids = list({c.get("user_id") for c in comments if c.get("user_id")})
        if author_ids:
            authors_docs = list(db.users.find(
                {"id": {"$in": author_ids}},
                {"id": 1, "avatar": 1, "name": 1, "_id": 0}
            ))
            author_map = {a["id"]: a for a in authors_docs}
            for c in comments:
                a = author_map.get(c.get("user_id")) or {}
                c["user_avatar"] = a.get("avatar")
                if a.get("name"):
                    c["user_name"] = a["name"]
    return PostResponse(**post)


@api_router.get("/posts", response_model=List[PostResponse])
def get_posts(current_user: dict = Depends(get_current_user)):
    # Get user's connections
    connections = db.connections.find({
        "$or": [
            {"from_user_id": current_user["id"], "status": "accepted"},
            {"to_user_id": current_user["id"], "status": "accepted"}
        ]
    }).to_list(1000)
    
    connection_ids = set()
    for conn in connections:
        if conn["from_user_id"] == current_user["id"]:
            connection_ids.add(conn["to_user_id"])
        else:
            connection_ids.add(conn["from_user_id"])
    
    # Include own posts and connections' posts
    connection_ids.add(current_user["id"])
    
    posts = list(db.posts.find({
        "$or": [
            {"user_id": {"$in": list(connection_ids)}},
            {"anonymous": True}
        ]
    }).sort("created_at", -1).limit(100))
    _bm = set(b["post_id"] for b in db.bookmarks.find({"user_id": current_user["id"]}, {"post_id": 1, "_id": 0}))
    _rp = set(r.get("reported_post_id") for r in db.reports.find({"reporter_id": current_user["id"]}, {"reported_post_id": 1, "_id": 0}) if r.get("reported_post_id"))
    for _p in posts:
        _p["bookmarked"] = _p.get("id") in _bm
        _p["reported"] = _p.get("id") in _rp
    return [_enrich_post(post) for post in posts]

@api_router.get("/posts/all", response_model=List[PostResponse])
def get_all_posts(current_user: dict = Depends(get_current_user)):
    posts = list(db.posts.find().sort("created_at", -1).limit(100))
    _bm = set(b["post_id"] for b in db.bookmarks.find({"user_id": current_user["id"]}, {"post_id": 1, "_id": 0}))
    _rp = set(r.get("reported_post_id") for r in db.reports.find({"reporter_id": current_user["id"]}, {"reported_post_id": 1, "_id": 0}) if r.get("reported_post_id"))
    for _p in posts:
        _p["bookmarked"] = _p.get("id") in _bm
        _p["reported"] = _p.get("id") in _rp
    return [_enrich_post(post) for post in posts]

@api_router.get("/posts/user/{user_id}", response_model=List[PostResponse])
def get_user_posts(user_id: str, current_user: dict = Depends(get_current_user)):
    posts = list(db.posts.find({"user_id": user_id}).sort("created_at", -1).limit(100))
    _bm = set(b["post_id"] for b in db.bookmarks.find({"user_id": current_user["id"]}, {"post_id": 1, "_id": 0}))
    _rp = set(r.get("reported_post_id") for r in db.reports.find({"reporter_id": current_user["id"]}, {"reported_post_id": 1, "_id": 0}) if r.get("reported_post_id"))
    for _p in posts:
        _p["bookmarked"] = _p.get("id") in _bm
        _p["reported"] = _p.get("id") in _rp
    return [_enrich_post(post) for post in posts]

@api_router.post("/posts/{post_id}/like")
def like_post(post_id: str, current_user: dict = Depends(get_current_user)):
    post = db.posts.find_one({"id": post_id})
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")
    
    if current_user["id"] in post.get("likes", []):
        # Unlike
        db.posts.update_one({"id": post_id}, {"$pull": {"likes": current_user["id"]}})
        return {"message": "Unliked", "liked": False}
    else:
        # Like
        db.posts.update_one({"id": post_id}, {"$push": {"likes": current_user["id"]}})
        return {"message": "Liked", "liked": True}

@api_router.post("/posts/{post_id}/comment", response_model=PostResponse)
def add_comment(post_id: str, comment_data: CommentCreate, current_user: dict = Depends(get_current_user)):
    post = db.posts.find_one({"id": post_id})
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")
    
    comment = {
        "id": str(uuid.uuid4()),
        "user_id": current_user["id"],
        "user_name": current_user["name"],
        "content": comment_data.content,
        "created_at": datetime.utcnow().isoformat()
    }
    
    db.posts.update_one({"id": post_id}, {"$push": {"comments": comment}})
    updated_post = db.posts.find_one({"id": post_id})
    return _enrich_post(updated_post)

@api_router.put("/posts/{post_id}/comments/{comment_id}", response_model=PostResponse)
def update_comment(post_id: str, comment_id: str, comment_data: CommentUpdate, current_user: dict = Depends(get_current_user)):
    post = db.posts.find_one({"id": post_id})
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")

    comment = next((c for c in post.get("comments", []) if c.get("id") == comment_id), None)
    if not comment:
        raise HTTPException(status_code=404, detail="Comment not found")
    if comment.get("user_id") != current_user["id"]:
        raise HTTPException(status_code=403, detail="Not authorized")

    content = comment_data.content.strip()
    if not content:
        raise HTTPException(status_code=400, detail="Comment content is required")

    db.posts.update_one(
        {"id": post_id, "comments.id": comment_id},
        {"$set": {"comments.$.content": content}}
    )

    updated_post = db.posts.find_one({"id": post_id})
    return _enrich_post(updated_post)

@api_router.put("/posts/{post_id}", response_model=PostResponse)
def update_post(post_id: str, post_data: PostUpdate, current_user: dict = Depends(get_current_user)):
    post = db.posts.find_one({"id": post_id})
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")
    if post["user_id"] != current_user["id"]:
        raise HTTPException(status_code=403, detail="Not authorized")

    update_dict = {}
    if post_data.content is not None:
        update_dict["content"] = post_data.content
    if post_data.link is not None:
        update_dict["link"] = post_data.link
    if post_data.category is not None:
        update_dict["category"] = post_data.category
    if post_data.tags is not None:
        update_dict["tags"] = post_data.tags
    if update_dict:
        db.posts.update_one({"id": post_id}, {"$set": update_dict})

    updated_post = db.posts.find_one({"id": post_id})
    return _enrich_post(updated_post)

@api_router.delete("/posts/{post_id}")
def delete_post(post_id: str, current_user: dict = Depends(get_current_user)):
    post = db.posts.find_one({"id": post_id})
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")
    if post["user_id"] != current_user["id"]:
        raise HTTPException(status_code=403, detail="Not authorized")
    
    db.posts.delete_one({"id": post_id})
    return {"message": "Post deleted"}

# ==================== BOOKMARK ROUTES ====================

@api_router.post("/posts/{post_id}/bookmark")
def toggle_bookmark(post_id: str, current_user: dict = Depends(get_current_user)):
    post = db.posts.find_one({"id": post_id})
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")
    existing = db.bookmarks.find_one({"user_id": current_user["id"], "post_id": post_id})
    if existing:
        db.bookmarks.delete_one({"_id": existing["_id"]})
        return {"message": "Bookmark removed", "bookmarked": False}
    db.bookmarks.insert_one({
        "id": str(uuid.uuid4()),
        "user_id": current_user["id"],
        "post_id": post_id,
        "created_at": datetime.utcnow(),
    })
    return {"message": "Post bookmarked", "bookmarked": True}

@api_router.get("/bookmarks", response_model=List[PostResponse])
def get_bookmarks(current_user: dict = Depends(get_current_user)):
    bookmarks = list(db.bookmarks.find({"user_id": current_user["id"]}).sort("created_at", -1).limit(200))
    post_ids = [b["post_id"] for b in bookmarks if b.get("post_id")]
    posts = list(db.posts.find({"id": {"$in": post_ids}}))
    posts_by_id = {p["id"]: p for p in posts}
    ordered = [posts_by_id[pid] for pid in post_ids if pid in posts_by_id]
    for p in ordered:
        p["bookmarked"] = True
    return [_enrich_post(p) for p in ordered]

# ==================== CONNECTION ROUTES ====================

def _enrich_connection_avatars(connections: list) -> list:
    """Attach from_user_avatar and to_user_avatar to connection dicts."""
    if not connections:
        return []
    user_ids = set()
    for c in connections:
        user_ids.add(c.get("from_user_id"))
        user_ids.add(c.get("to_user_id"))
    user_ids.discard(None)
    users_cursor = db.users.find(
        {"id": {"$in": list(user_ids)}},
        {"id": 1, "avatar": 1, "_id": 0}
    )
    avatar_map = {u["id"]: u.get("avatar") for u in users_cursor}
    for c in connections:
        c["from_user_avatar"] = avatar_map.get(c.get("from_user_id"))
        c["to_user_avatar"] = avatar_map.get(c.get("to_user_id"))
    return connections


@api_router.post("/connections", response_model=ConnectionResponse)
def create_connection_request(request: ConnectionRequest, current_user: dict = Depends(get_current_user)):
    # Check if connection already exists
    existing = db.connections.find_one({
        "$or": [
            {"from_user_id": current_user["id"], "to_user_id": request.to_user_id},
            {"from_user_id": request.to_user_id, "to_user_id": current_user["id"]}
        ]
    })
    if existing:
        raise HTTPException(status_code=400, detail="Connection request already exists")
    
    to_user = db.users.find_one({"id": request.to_user_id})
    if not to_user:
        raise HTTPException(status_code=404, detail="User not found")
    
    conn_id = str(uuid.uuid4())
    conn_dict = {
        "id": conn_id,
        "from_user_id": current_user["id"],
        "from_user_name": current_user["name"],
        "from_user_headline": current_user.get("headline", ""),
        "to_user_id": request.to_user_id,
        "to_user_name": to_user["name"],
        "to_user_headline": to_user.get("headline", ""),
        "status": "pending",
        "created_at": datetime.utcnow()
    }
    
    db.connections.insert_one(conn_dict)
    conn_dict["from_user_avatar"] = current_user.get("avatar")
    conn_dict["to_user_avatar"] = to_user.get("avatar")
    _notify_connection_request(
        request.to_user_id,
        current_user.get("name", "A Peers member"),
        current_user.get("headline", ""),
    )
    return ConnectionResponse(**conn_dict)

@api_router.get("/connections", response_model=List[ConnectionResponse])
def get_connections(current_user: dict = Depends(get_current_user)):
    connections = db.connections.find({
        "$or": [
            {"from_user_id": current_user["id"], "status": "accepted"},
            {"to_user_id": current_user["id"], "status": "accepted"}
        ]
    }).to_list(1000)
    connections = _enrich_connection_avatars(connections)
    return [ConnectionResponse(**conn) for conn in connections]

@api_router.get("/connections/pending", response_model=List[ConnectionResponse])
def get_pending_connections(current_user: dict = Depends(get_current_user)):
    connections = db.connections.find({
        "to_user_id": current_user["id"],
        "status": "pending"
    }).to_list(100)
    connections = _enrich_connection_avatars(connections)
    return [ConnectionResponse(**conn) for conn in connections]

@api_router.get("/connections/sent", response_model=List[ConnectionResponse])
def get_sent_connections(current_user: dict = Depends(get_current_user)):
    connections = db.connections.find({
        "from_user_id": current_user["id"],
        "status": "pending"
    }).to_list(100)
    connections = _enrich_connection_avatars(connections)
    return [ConnectionResponse(**conn) for conn in connections]

@api_router.put("/connections/{connection_id}/accept")
def accept_connection(connection_id: str, current_user: dict = Depends(get_current_user)):
    connection = db.connections.find_one({"id": connection_id})
    if not connection:
        raise HTTPException(status_code=404, detail="Connection not found")
    if connection["to_user_id"] != current_user["id"]:
        raise HTTPException(status_code=403, detail="Not authorized")
    
    db.connections.update_one({"id": connection_id}, {"$set": {"status": "accepted"}})
    return {"message": "Connection accepted"}

@api_router.put("/connections/{connection_id}/reject")
def reject_connection(connection_id: str, current_user: dict = Depends(get_current_user)):
    connection = db.connections.find_one({"id": connection_id})
    if not connection:
        raise HTTPException(status_code=404, detail="Connection not found")
    if connection["to_user_id"] != current_user["id"]:
        raise HTTPException(status_code=403, detail="Not authorized")
    
    db.connections.delete_one({"id": connection_id})
    return {"message": "Connection rejected"}

@api_router.delete("/connections/{user_id}")
def remove_connection(user_id: str, current_user: dict = Depends(get_current_user)):
    result = db.connections.delete_one({
        "$or": [
            {"from_user_id": current_user["id"], "to_user_id": user_id, "status": "accepted"},
            {"from_user_id": user_id, "to_user_id": current_user["id"], "status": "accepted"}
        ]
    })
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Connection not found")
    return {"message": "Connection removed"}

@api_router.get("/connections/status/{user_id}")
def get_connection_status(user_id: str, current_user: dict = Depends(get_current_user)):
    connection = db.connections.find_one({
        "$or": [
            {"from_user_id": current_user["id"], "to_user_id": user_id},
            {"from_user_id": user_id, "to_user_id": current_user["id"]}
        ]
    })
    
    if not connection:
        return {"status": "none", "connection_id": None}
    
    is_sender = connection["from_user_id"] == current_user["id"]
    return {
        "status": connection["status"],
        "connection_id": connection["id"],
        "is_sender": is_sender
    }

# ==================== MESSAGE ROUTES ====================

@api_router.post("/messages", response_model=MessageResponse)
def send_message(message_data: MessageCreate, current_user: dict = Depends(get_current_user)):
    to_user = db.users.find_one({"id": message_data.to_user_id})
    if not to_user:
        raise HTTPException(status_code=404, detail="User not found")
    
    msg_id = str(uuid.uuid4())
    msg_dict = {
        "id": msg_id,
        "from_user_id": current_user["id"],
        "from_user_name": current_user["name"],
        "to_user_id": message_data.to_user_id,
        "to_user_name": to_user["name"],
        "content": message_data.content,
        "read": False,
        "created_at": datetime.utcnow()
    }
    
    db.messages.insert_one(msg_dict)
    _notify_new_message(
        message_data.to_user_id,
        current_user.get("name", "A Peers member"),
        message_data.content,
    )
    return MessageResponse(**msg_dict)

@api_router.get("/messages/conversations", response_model=List[ConversationResponse])
def get_conversations(current_user: dict = Depends(get_current_user)):
    # Get all messages involving the user
    messages = list(db.messages.find({
        "$or": [
            {"from_user_id": current_user["id"]},
            {"to_user_id": current_user["id"]}
        ]
    }).sort("created_at", -1).limit(1000))
    
    conversations = {}
    for msg in messages:
        other_user_id = msg["to_user_id"] if msg["from_user_id"] == current_user["id"] else msg["from_user_id"]
        other_user_name = msg["to_user_name"] if msg["from_user_id"] == current_user["id"] else msg["from_user_name"]
        
        if other_user_id not in conversations:
            # Get user headline and avatar
            other_user = db.users.find_one({"id": other_user_id})
            headline = other_user.get("headline", "") if other_user else ""
            avatar = other_user.get("avatar") if other_user else None

            # Count unread
            unread = db.messages.count_documents({
                "from_user_id": other_user_id,
                "to_user_id": current_user["id"],
                "read": False
            })

            conversations[other_user_id] = ConversationResponse(
                user_id=other_user_id,
                user_name=other_user_name,
                user_headline=headline,
                user_avatar=avatar,
                last_message=msg["content"],
                last_message_time=msg["created_at"],
                unread_count=unread
            )
    
    return list(conversations.values())

@api_router.get("/messages/{user_id}", response_model=List[MessageResponse])
def get_messages_with_user(user_id: str, current_user: dict = Depends(get_current_user)):
    messages = list(db.messages.find({
        "$or": [
            {"from_user_id": current_user["id"], "to_user_id": user_id},
            {"from_user_id": user_id, "to_user_id": current_user["id"]}
        ]
    }).sort("created_at", 1).limit(1000))
    
    # Mark messages as read
    db.messages.update_many(
        {"from_user_id": user_id, "to_user_id": current_user["id"], "read": False},
        {"$set": {"read": True}}
    )
    
    return [MessageResponse(**msg) for msg in messages]

# ==================== GROUP CHAT ROUTES ====================

def _serialize_group(group: dict, current_user_id: str) -> GroupResponse:
    """Convert DB group document to GroupResponse."""
    member_ids = group.get("member_ids", [])
    members_docs = list(db.users.find(
        {"id": {"$in": member_ids}},
        {"id": 1, "name": 1, "avatar": 1, "headline": 1, "_id": 0}
    ))
    members = [
        GroupMemberInfo(
            id=m["id"],
            name=m.get("name", ""),
            avatar=m.get("avatar"),
            headline=m.get("headline", "")
        )
        for m in members_docs
    ]
    owner = db.users.find_one({"id": group["owner_id"]}, {"name": 1})
    owner_name = owner.get("name", "") if owner else ""

    last_msg_doc = db.group_messages.find_one(
        {"group_id": group["id"]},
        sort=[("created_at", -1)]
    )
    last_message = last_msg_doc["content"] if last_msg_doc else None
    last_message_time = last_msg_doc["created_at"] if last_msg_doc else None

    # Unread count: messages after current user's last-read timestamp
    reads = group.get("read_state", {}) or {}
    last_read = reads.get(current_user_id)
    unread_filter = {"group_id": group["id"], "from_user_id": {"$ne": current_user_id}}
    if last_read:
        unread_filter["created_at"] = {"$gt": last_read}
    unread_count = db.group_messages.count_documents(unread_filter)

    return GroupResponse(
        id=group["id"],
        name=group["name"],
        avatar=group.get("avatar"),
        owner_id=group["owner_id"],
        owner_name=owner_name,
        members=members,
        member_count=len(member_ids),
        last_message=last_message,
        last_message_time=last_message_time,
        unread_count=unread_count,
        created_at=group["created_at"],
    )


@api_router.post("/groups", response_model=GroupResponse)
def create_group(payload: GroupCreate, current_user: dict = Depends(get_current_user)):
    name = payload.name.strip()
    if not name:
        raise HTTPException(status_code=400, detail="Group name is required")
    if len(name) > 60:
        raise HTTPException(status_code=400, detail="Group name too long")

    # Sanitize member ids: must be connected to current user (accepted connection) or the user themselves
    member_ids = list({mid for mid in payload.member_ids if mid and mid != current_user["id"]})
    if member_ids:
        connected = db.connections.find({
            "$or": [
                {"from_user_id": current_user["id"], "to_user_id": {"$in": member_ids}, "status": "accepted"},
                {"to_user_id": current_user["id"], "from_user_id": {"$in": member_ids}, "status": "accepted"},
            ]
        })
        allowed = set()
        for conn in connected:
            allowed.add(conn["to_user_id"] if conn["from_user_id"] == current_user["id"] else conn["from_user_id"])
        member_ids = [m for m in member_ids if m in allowed]

    # Always include the owner
    all_members = list({current_user["id"], *member_ids})

    group_id = str(uuid.uuid4())
    now = datetime.utcnow()
    group_doc = {
        "id": group_id,
        "name": name,
        "avatar": payload.avatar,
        "owner_id": current_user["id"],
        "member_ids": all_members,
        "read_state": {current_user["id"]: now},
        "created_at": now,
    }
    db.groups.insert_one(group_doc)
    return _serialize_group(group_doc, current_user["id"])


@api_router.get("/groups", response_model=List[GroupResponse])
def list_my_groups(current_user: dict = Depends(get_current_user)):
    groups = list(db.groups.find({"member_ids": current_user["id"]}).sort("created_at", -1).limit(200))
    result = [_serialize_group(g, current_user["id"]) for g in groups]
    # Sort by last_message_time desc, then by created_at desc
    result.sort(key=lambda g: (g.last_message_time or g.created_at), reverse=True)
    return result


@api_router.get("/groups/{group_id}", response_model=GroupResponse)
def get_group(group_id: str, current_user: dict = Depends(get_current_user)):
    group = db.groups.find_one({"id": group_id})
    if not group:
        raise HTTPException(status_code=404, detail="Group not found")
    if current_user["id"] not in group.get("member_ids", []):
        raise HTTPException(status_code=403, detail="You are not a member of this group")
    return _serialize_group(group, current_user["id"])


@api_router.put("/groups/{group_id}", response_model=GroupResponse)
def update_group(group_id: str, payload: GroupUpdate, current_user: dict = Depends(get_current_user)):
    group = db.groups.find_one({"id": group_id})
    if not group:
        raise HTTPException(status_code=404, detail="Group not found")
    if group["owner_id"] != current_user["id"]:
        raise HTTPException(status_code=403, detail="Only the group owner can update it")
    updates = {}
    if payload.name is not None:
        name = payload.name.strip()
        if not name:
            raise HTTPException(status_code=400, detail="Group name cannot be empty")
        if len(name) > 60:
            raise HTTPException(status_code=400, detail="Group name too long")
        updates["name"] = name
    if payload.avatar is not None:
        updates["avatar"] = payload.avatar or None
    if updates:
        db.groups.update_one({"id": group_id}, {"$set": updates})
        group.update(updates)
    return _serialize_group(group, current_user["id"])


@api_router.delete("/groups/{group_id}")
def delete_group(group_id: str, current_user: dict = Depends(get_current_user)):
    group = db.groups.find_one({"id": group_id})
    if not group:
        raise HTTPException(status_code=404, detail="Group not found")
    if group["owner_id"] != current_user["id"]:
        raise HTTPException(status_code=403, detail="Only the group owner can delete it")
    db.groups.delete_one({"id": group_id})
    db.group_messages.delete_many({"group_id": group_id})
    return {"success": True}


@api_router.post("/groups/{group_id}/members", response_model=GroupResponse)
def add_members(group_id: str, payload: GroupMembersAdd, current_user: dict = Depends(get_current_user)):
    group = db.groups.find_one({"id": group_id})
    if not group:
        raise HTTPException(status_code=404, detail="Group not found")
    if current_user["id"] not in group.get("member_ids", []):
        raise HTTPException(status_code=403, detail="You are not a member of this group")

    new_ids = [uid for uid in payload.user_ids if uid and uid not in group.get("member_ids", [])]
    if new_ids:
        # Only allow users that current user is connected with
        connected = db.connections.find({
            "$or": [
                {"from_user_id": current_user["id"], "to_user_id": {"$in": new_ids}, "status": "accepted"},
                {"to_user_id": current_user["id"], "from_user_id": {"$in": new_ids}, "status": "accepted"},
            ]
        })
        allowed = set()
        for conn in connected:
            allowed.add(conn["to_user_id"] if conn["from_user_id"] == current_user["id"] else conn["from_user_id"])
        new_ids = [uid for uid in new_ids if uid in allowed]

    if new_ids:
        db.groups.update_one(
            {"id": group_id},
            {"$addToSet": {"member_ids": {"$each": new_ids}}}
        )
        group["member_ids"] = list({*group.get("member_ids", []), *new_ids})
    return _serialize_group(group, current_user["id"])


@api_router.delete("/groups/{group_id}/members/{user_id}", response_model=GroupResponse)
def remove_member(group_id: str, user_id: str, current_user: dict = Depends(get_current_user)):
    group = db.groups.find_one({"id": group_id})
    if not group:
        raise HTTPException(status_code=404, detail="Group not found")
    if current_user["id"] not in group.get("member_ids", []):
        raise HTTPException(status_code=403, detail="You are not a member of this group")

    is_owner = group["owner_id"] == current_user["id"]
    is_self = user_id == current_user["id"]

    if not is_owner and not is_self:
        raise HTTPException(status_code=403, detail="Only the owner can remove other members")

    if is_owner and is_self:
        # Owner leaves: transfer ownership to next member, or delete if last
        remaining = [m for m in group.get("member_ids", []) if m != user_id]
        if remaining:
            db.groups.update_one(
                {"id": group_id},
                {"$set": {"owner_id": remaining[0]}, "$pull": {"member_ids": user_id}}
            )
        else:
            db.groups.delete_one({"id": group_id})
            db.group_messages.delete_many({"group_id": group_id})
            return {"id": group_id, "name": group["name"], "owner_id": user_id,
                    "owner_name": current_user.get("name", ""), "members": [],
                    "member_count": 0, "created_at": group["created_at"]}
    else:
        db.groups.update_one({"id": group_id}, {"$pull": {"member_ids": user_id}})

    group = db.groups.find_one({"id": group_id})
    return _serialize_group(group, current_user["id"])


@api_router.get("/groups/{group_id}/messages", response_model=List[GroupMessageResponse])
def get_group_messages(group_id: str, current_user: dict = Depends(get_current_user)):
    group = db.groups.find_one({"id": group_id})
    if not group:
        raise HTTPException(status_code=404, detail="Group not found")
    if current_user["id"] not in group.get("member_ids", []):
        raise HTTPException(status_code=403, detail="You are not a member of this group")

    messages = list(db.group_messages.find({"group_id": group_id}).sort("created_at", 1).limit(1000))
    # Mark as read for this user
    db.groups.update_one(
        {"id": group_id},
        {"$set": {f"read_state.{current_user['id']}": datetime.utcnow()}}
    )
    return [GroupMessageResponse(**m) for m in messages]


@api_router.post("/groups/{group_id}/messages", response_model=GroupMessageResponse)
def send_group_message(group_id: str, payload: GroupMessageCreate, current_user: dict = Depends(get_current_user)):
    group = db.groups.find_one({"id": group_id})
    if not group:
        raise HTTPException(status_code=404, detail="Group not found")
    if current_user["id"] not in group.get("member_ids", []):
        raise HTTPException(status_code=403, detail="You are not a member of this group")

    content = payload.content.strip()
    if not content:
        raise HTTPException(status_code=400, detail="Message content is required")

    msg = {
        "id": str(uuid.uuid4()),
        "group_id": group_id,
        "from_user_id": current_user["id"],
        "from_user_name": current_user.get("name", ""),
        "from_user_avatar": current_user.get("avatar"),
        "content": content,
        "created_at": datetime.utcnow(),
    }
    db.group_messages.insert_one(msg)
    # Update sender's read timestamp
    db.groups.update_one(
        {"id": group_id},
        {"$set": {f"read_state.{current_user['id']}": msg["created_at"]}}
    )
    msg.pop("_id", None)
    return GroupMessageResponse(**msg)


# ==================== PEER CIRCLES ====================

class CircleCreate(BaseModel):
    name: str
    topic: Optional[str] = ""
    city: Optional[str] = ""
    max_members: Optional[int] = 8

@api_router.get("/circles")
def list_circles(current_user: dict = Depends(get_current_user)):
    circles = list(db.groups.find({"is_circle": True}).sort("created_at", -1).limit(100))
    result = []
    for c in circles:
        member_ids = c.get("member_ids", [])
        owner = db.users.find_one({"id": c["owner_id"]}, {"name": 1})
        result.append({
            "id": c["id"],
            "name": c["name"],
            "topic": c.get("topic", ""),
            "city": c.get("city", ""),
            "member_count": len(member_ids),
            "max_members": c.get("max_members", 8),
            "is_member": current_user["id"] in member_ids,
            "owner_name": owner.get("name", "") if owner else "",
        })
    return result

@api_router.post("/circles")
def create_circle(payload: CircleCreate, current_user: dict = Depends(get_current_user)):
    name = payload.name.strip()
    if not name:
        raise HTTPException(status_code=400, detail="Circle name is required")
    if len(name) > 60:
        raise HTTPException(status_code=400, detail="Circle name too long")
    max_members = payload.max_members or 8
    if max_members < 2 or max_members > 20:
        raise HTTPException(status_code=400, detail="Max members must be between 2 and 20")
    now = datetime.utcnow()
    doc = {
        "id": str(uuid.uuid4()),
        "name": name,
        "avatar": None,
        "owner_id": current_user["id"],
        "member_ids": [current_user["id"]],
        "read_state": {current_user["id"]: now},
        "is_circle": True,
        "topic": (payload.topic or "").strip(),
        "city": (payload.city or "").strip(),
        "max_members": max_members,
        "created_at": now,
    }
    db.groups.insert_one(doc)
    doc.pop("_id", None)
    doc.pop("read_state", None)
    return doc

@api_router.post("/circles/{circle_id}/join")
def join_circle(circle_id: str, current_user: dict = Depends(get_current_user)):
    c = db.groups.find_one({"id": circle_id, "is_circle": True})
    if not c:
        raise HTTPException(status_code=404, detail="Circle not found")
    member_ids = c.get("member_ids", [])
    if current_user["id"] in member_ids:
        return {"message": "Already a member"}
    if len(member_ids) >= c.get("max_members", 8):
        raise HTTPException(status_code=400, detail="Circle is full")
    db.groups.update_one(
        {"id": circle_id},
        {"$addToSet": {"member_ids": current_user["id"]},
         "$set": {f"read_state.{current_user['id']}": datetime.utcnow()}}
    )
    return {"message": "Joined circle"}

# ==================== EVENTS / ROUNDTABLES ====================

class EventCreate(BaseModel):
    title: str
    city: Optional[str] = ""
    date: Optional[str] = ""  # "YYYY-MM-DD HH:MM"
    description: Optional[str] = ""
    max_seats: Optional[int] = None

@api_router.get("/events")
def list_events(current_user: dict = Depends(get_current_user)):
    events = list(db.events.find({}, {"_id": 0}).sort("date", 1).limit(100))
    result = []
    for ev in events:
        rsvps = ev.get("rsvps", [])
        names = []
        if rsvps:
            docs = db.users.find({"id": {"$in": rsvps}}, {"name": 1, "_id": 0}).limit(50)
            names = [d.get("name", "") for d in docs]
        ev["rsvp_count"] = len(rsvps)
        ev["attendee_names"] = names
        ev["me"] = current_user["id"] in rsvps
        ev.pop("rsvps", None)
        result.append(ev)
    return result

@api_router.post("/admin/events")
def create_event(payload: EventCreate, admin_user: dict = Depends(get_admin_user)):
    title = payload.title.strip()
    if not title:
        raise HTTPException(status_code=400, detail="Event title is required")
    doc = {
        "id": str(uuid.uuid4()),
        "title": title,
        "city": (payload.city or "").strip(),
        "date": (payload.date or "").strip(),
        "description": (payload.description or "").strip(),
        "max_seats": payload.max_seats,
        "rsvps": [],
        "created_by": admin_user["email"],
        "created_by_id": admin_user["id"],
        "created_at": datetime.utcnow(),
    }
    db.events.insert_one(doc)
    doc.pop("_id", None)
    return doc

@api_router.delete("/admin/events/{event_id}")
def delete_event(event_id: str, admin_user: dict = Depends(get_admin_user)):
    result = db.events.delete_one({"id": event_id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Event not found")
    return {"message": "Event deleted"}

@api_router.post("/events/{event_id}/rsvp")
def rsvp_event(event_id: str, current_user: dict = Depends(get_current_user)):
    ev = db.events.find_one({"id": event_id})
    if not ev:
        raise HTTPException(status_code=404, detail="Event not found")
    rsvps = ev.get("rsvps", [])
    if current_user["id"] in rsvps:
        db.events.update_one({"id": event_id}, {"$pull": {"rsvps": current_user["id"]}})
        return {"message": "RSVP removed", "going": False}
    if ev.get("max_seats") and len(rsvps) >= ev["max_seats"]:
        raise HTTPException(status_code=400, detail="Event is full")
    db.events.update_one({"id": event_id}, {"$addToSet": {"rsvps": current_user["id"]}})

    # Notify the event creator that someone registered
    creator_id = ev.get("created_by_id")
    if not creator_id and ev.get("created_by"):
        creator_lookup = db.users.find_one({"email": ev["created_by"]}, {"id": 1})
        creator_id = creator_lookup["id"] if creator_lookup else None
    if creator_id and creator_id != current_user["id"]:
        creator = db.users.find_one({"id": creator_id})
        if creator:
            db.messages.insert_one({
                "id": str(uuid.uuid4()),
                "from_user_id": current_user["id"],
                "from_user_name": current_user.get("name", ""),
                "to_user_id": creator_id,
                "to_user_name": creator.get("name", ""),
                "content": "S-a inscris la evenimentul tau: " + ev.get("title", ""),
                "read": False,
                "created_at": datetime.utcnow()
            })

    return {"message": "RSVP confirmed", "going": True}

# ==================== HEALTH CHECK ====================

@api_router.get("/health")
def health_check():
    return {"status": "ok", "timestamp": datetime.utcnow().isoformat()}

# ==================== ADMIN ROUTES ====================

@api_router.get("/admin/stats", response_model=AdminStats)
def get_admin_stats(admin_user: dict = Depends(get_admin_user)):
    today = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
    
    total_users = db.users.count_documents({})
    total_posts = db.posts.count_documents({})
    total_connections = db.connections.count_documents({"status": "accepted"})
    total_messages = db.messages.count_documents({})
    pending_reports = db.reports.count_documents({"status": "pending"})
    blocked_users = db.users.count_documents({"is_blocked": True})
    new_users_today = db.users.count_documents({"created_at": {"$gte": today}})
    new_posts_today = db.posts.count_documents({"created_at": {"$gte": today}})
    
    return AdminStats(
        total_users=total_users,
        total_posts=total_posts,
        total_connections=total_connections,
        total_messages=total_messages,
        pending_reports=pending_reports,
        blocked_users=blocked_users,
        new_users_today=new_users_today,
        new_posts_today=new_posts_today
    )

def _run_weekly_digest(preview: bool = False):
    """Build the weekly re-engagement digest. If preview=True, returns the rendered HTML +
    the week's counts + recipient count WITHOUT sending. Otherwise sends to all members and returns counts."""
    week_ago = datetime.utcnow() - timedelta(days=7)
    today = datetime.utcnow().strftime("%Y-%m-%d")
    sent, skipped = 0, 0

    new_users = db.users.count_documents({"created_at": {"$gte": week_ago}})
    new_posts = db.posts.count_documents({"created_at": {"$gte": week_ago}})
    new_connections = db.connections.count_documents({"created_at": {"$gte": week_ago}, "status": "accepted"})
    new_asks = db.board.count_documents({"type": "ask", "status": "open", "created_at": {"$gte": week_ago}})
    new_offers = db.board.count_documents({"type": "offer", "status": "open", "created_at": {"$gte": week_ago}})

    # Recent open asks (titles) to pull people back
    recent_asks = list(db.board.find({"type": "ask", "status": "open"}, {"title": 1, "_id": 0}).sort("created_at", -1).limit(3))
    asks_html = "".join(f'<li style="margin:4px 0">{esc(a.get("title",""))}</li>' for a in recent_asks)
    # Upcoming events (date string >= today)
    upcoming = [e for e in db.events.find({}, {"title": 1, "date": 1, "city": 1, "_id": 0}).sort("date", 1).limit(20)
                if (e.get("date") or "")[:10] >= today][:3]
    events_html = "".join(f'<li style="margin:4px 0">{esc(e.get("title",""))} — {esc((e.get("date") or "")[:16])} {esc(e.get("city",""))}</li>' for e in upcoming)

    blocks = ""
    if asks_html:
        blocks += f'<p style="margin:16px 0 4px;font-weight:700">🤝 Cineva are nevoie de ajutor:</p><ul style="margin:0;padding-left:18px;color:#444">{asks_html}</ul>'
    if events_html:
        blocks += f'<p style="margin:16px 0 4px;font-weight:700">📅 Evenimente care vin:</p><ul style="margin:0;padding-left:18px;color:#444">{events_html}</ul>'

    def render(name: str) -> str:
        return (f"""<div style="font-family:-apple-system,sans-serif;max-width:480px;margin:0 auto;padding:20px">
            <h2 style="color:#00BCD4">📈 Săptămâna ta pe Peers</h2>
            <p>Salut {esc(name) if name else ''},</p>
            <p>Ce s-a întâmplat în ultimele 7 zile:</p>
            <table style="width:100%;border-collapse:collapse;margin:16px 0">
              <tr><td style="padding:8px;border-bottom:1px solid #eee">👥 Membri noi</td><td style="padding:8px;border-bottom:1px solid #eee;text-align:right;font-weight:700">{new_users}</td></tr>
              <tr><td style="padding:8px;border-bottom:1px solid #eee">💬 Postări & dileme</td><td style="padding:8px;border-bottom:1px solid #eee;text-align:right;font-weight:700">{new_posts}</td></tr>
              <tr><td style="padding:8px;border-bottom:1px solid #eee">🙋 Cereri noi (Caut)</td><td style="padding:8px;border-bottom:1px solid #eee;text-align:right;font-weight:700">{new_asks}</td></tr>
              <tr><td style="padding:8px">🎁 Oferte noi</td><td style="padding:8px;text-align:right;font-weight:700">{new_offers}</td></tr>
            </table>
            {blocks}
            <p style="margin-top:18px">Cineva poate aștepta răspunsul tău — <a href="{APP_URL}/board" style="color:#00BCD4">vezi ce e nou</a>.</p>
            <p style="color:#888;font-size:12px">— Peers by NetWorth</p></div>""")

    active_users = list(db.users.find(
        {"email": {"$ne": ""}, "is_blocked": {"$ne": True}},
        {"email": 1, "name": 1, "_id": 0},
    ).limit(1000))
    recipients = [u for u in active_users if (u.get("email") or "").strip()]

    counts = {"new_users": new_users, "new_posts": new_posts, "new_connections": new_connections,
              "new_asks": new_asks, "new_offers": new_offers,
              "recent_asks": [a.get("title", "") for a in recent_asks],
              "upcoming": [{"title": e.get("title", ""), "date": (e.get("date") or "")[:16], "city": e.get("city", "")} for e in upcoming]}

    if preview:
        # Sample greeting uses the first recipient's name so the admin sees it as members will.
        sample_name = (recipients[0].get("name") or "").split()[0] if recipients else ""
        return {"html": render(sample_name), "recipients": len(recipients), "counts": counts}

    for u in recipients:
        name = (u.get("name") or "there").split()[0]
        ok = _send_email(u["email"].strip(), "Peers — recapul săptămânii", render(name))
        if ok:
            sent += 1
        else:
            skipped += 1
    return {"sent": sent, "skipped": skipped}

@api_router.get("/admin/digest/preview")
def preview_weekly_digest(admin_user: dict = Depends(get_admin_user)):
    """Build the weekly digest and return its HTML + counts + recipient count, WITHOUT sending."""
    return _run_weekly_digest(preview=True)

@api_router.post("/admin/digest")
def send_weekly_digest(admin_user: dict = Depends(get_admin_user)):
    """Send the weekly digest now (admin-triggered)."""
    return _run_weekly_digest()

@api_router.get("/cron/digest")
def cron_digest(key: str = ""):
    """Weekly digest trigger for cron-job.org. Requires ?key=DIGEST_KEY."""
    expected = os.environ.get("DIGEST_KEY", "")
    if not expected or key != expected:
        raise HTTPException(status_code=403, detail="Forbidden")
    return _run_weekly_digest()

@api_router.get("/admin/users", response_model=List[UserResponse])
def get_all_users_admin(admin_user: dict = Depends(get_admin_user)):
    users = list(db.users.find().sort("created_at", -1).limit(500))
    result = []
    for user in users:
        connections_count = get_connections_count(user["id"])
        is_admin = user.get("is_admin", False) or user.get("email") in ADMIN_EMAILS
        result.append(UserResponse(
            id=user["id"],
            email=user["email"],
            name=user["name"],
            bio=user.get("bio", ""),
            headline=user.get("headline", ""),
            location=user.get("location", ""),
            phone=user.get("phone", ""),
            skills=user.get("skills", []),
            experience=user.get("experience", []),
            language=user.get("language", "en"),
            created_at=user["created_at"],
            connections_count=connections_count,
            avatar=user.get("avatar"),
            can_help_with=user.get("can_help_with", []),
            wins=user.get("wins", []),
            is_admin=is_admin,
            is_blocked=user.get("is_blocked", False)
        ))
    return result

@api_router.put("/admin/users/{user_id}")
def update_user_admin(user_id: str, update_data: AdminUserUpdate, admin_user: dict = Depends(get_admin_user)):
    user = db.users.find_one({"id": user_id})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    update_dict = {}
    if update_data.is_admin is not None:
        update_dict["is_admin"] = update_data.is_admin
    if update_data.is_blocked is not None:
        update_dict["is_blocked"] = update_data.is_blocked
    if update_data.new_password:
        # Admin forced reset: hash new password, invalidate any pending email reset code
        update_dict["password_hash"] = get_password_hash(update_data.new_password)
        update_dict["password_reset_by"] = admin_user.get("email", "admin")
        update_dict["password_reset_at"] = datetime.utcnow()
        db.password_resets.delete_one({"user_id": user_id})

    if update_dict:
        db.users.update_one({"id": user_id}, {"$set": update_dict})

    return {"message": "User updated successfully"}

@api_router.delete("/admin/users/{user_id}")
def delete_user_admin(user_id: str, admin_user: dict = Depends(get_admin_user)):
    user = db.users.find_one({"id": user_id})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Delete user and all their data
    db.users.delete_one({"id": user_id})
    db.posts.delete_many({"user_id": user_id})
    db.connections.delete_many({"$or": [{"from_user_id": user_id}, {"to_user_id": user_id}]})
    db.messages.delete_many({"$or": [{"from_user_id": user_id}, {"to_user_id": user_id}]})
    
    return {"message": "User deleted successfully"}

class InviteCreate(BaseModel):
    max_uses: Optional[int] = None
    note: Optional[str] = ""

@api_router.post("/admin/invites")
def create_invite(payload: InviteCreate, admin_user: dict = Depends(get_admin_user)):
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    code = "".join(secrets.choice(alphabet) for _ in range(8))
    doc = {
        "code": code,
        "active": True,
        "max_uses": payload.max_uses,
        "used_count": 0,
        "used_by": [],
        "note": payload.note or "",
        "created_by": admin_user["email"],
        "created_at": datetime.utcnow()
    }
    db.invite_codes.insert_one(doc)
    doc.pop("_id", None)
    return doc

@api_router.get("/admin/invites")
def list_invites(admin_user: dict = Depends(get_admin_user)):
    return list(db.invite_codes.find({}, {"_id": 0}).sort("created_at", -1).limit(200))

@api_router.delete("/admin/invites/{code}")
def deactivate_invite(code: str, admin_user: dict = Depends(get_admin_user)):
    result = db.invite_codes.update_one({"code": code.upper()}, {"$set": {"active": False}})
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Invite code not found")
    return {"message": "Invite code deactivated"}

@api_router.get("/admin/members/export")
def export_members(admin_user: dict = Depends(get_admin_user)):
    from fastapi.responses import StreamingResponse
    from openpyxl import Workbook
    from openpyxl.styles import Font
    import io

    # Fallback map for members registered before invite tracking: email -> (code, note)
    code_map = {}
    for inv in db.invite_codes.find({}, {"_id": 0, "code": 1, "note": 1, "used_by": 1}):
        for em in inv.get("used_by", []):
            code_map.setdefault(em, (inv["code"], inv.get("note", "")))

    wb = Workbook()
    ws = wb.active
    ws.title = "Members"
    headers = ["Name", "Email", "Headline", "Location", "Language",
               "Registered at", "Invite code", "Source", "Admin", "Blocked"]
    ws.append(headers)
    for cell in ws[1]:
        cell.font = Font(bold=True)

    for u in db.users.find().sort("created_at", 1):
        code = u.get("invite_code") or ""
        source = u.get("invite_source") or ""
        if not code and u.get("email") in code_map:
            code, mapped_note = code_map[u["email"]]
            source = source or mapped_note
        created = u.get("created_at")
        ws.append([
            u.get("name", ""),
            u.get("email", ""),
            u.get("headline", ""),
            u.get("location", ""),
            u.get("language", ""),
            created.strftime("%Y-%m-%d %H:%M") if created else "",
            code,
            source,
            "yes" if u.get("is_admin") else "",
            "yes" if u.get("is_blocked") else "",
        ])

    widths = [22, 30, 26, 18, 10, 17, 13, 22, 8, 8]
    for i, w in enumerate(widths, start=1):
        ws.column_dimensions[ws.cell(row=1, column=i).column_letter].width = w

    buf = io.BytesIO()
    wb.save(buf)
    buf.seek(0)
    filename = "peers-members-" + datetime.utcnow().strftime("%Y-%m-%d") + ".xlsx"
    return StreamingResponse(
        buf,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )

@api_router.get("/admin/posts")
def get_all_posts_admin(admin_user: dict = Depends(get_admin_user)):
    posts = list(db.posts.find().sort("created_at", -1).limit(500))
    # Resolve real author name/email for every post (including anonymous "dilema" posts,
    # whose author is masked in the public feed). Admin needs to see the truth.
    user_ids = {p.get("user_id") for p in posts if p.get("user_id")}
    authors = {}
    if user_ids:
        for u in db.users.find({"id": {"$in": list(user_ids)}}, {"id": 1, "name": 1, "email": 1, "_id": 0}):
            authors[u["id"]] = u
    for p in posts:
        p.pop("_id", None)  # ObjectId not JSON-serializable -> would 500
        for c in (p.get("comments") or []):
            c.pop("_id", None)
        a = authors.get(p.get("user_id"))
        p["author_name"] = a.get("name", "") if a else None
        p["author_email"] = a.get("email", "") if a else None
        if p.get("anonymous"):
            p["masked_as"] = "🎭 Anonymous member"  # visible only in admin view
    return posts

@api_router.delete("/admin/posts/{post_id}")
def delete_post_admin(post_id: str, admin_user: dict = Depends(get_admin_user)):
    post = db.posts.find_one({"id": post_id})
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")
    
    db.posts.delete_one({"id": post_id})
    return {"message": "Post deleted successfully"}

@api_router.post("/reports", response_model=ReportResponse)
def create_report(report_data: ReportCreate, current_user: dict = Depends(get_current_user)):
    report_id = str(uuid.uuid4())
    
    reported_user_name = None
    if report_data.reported_user_id:
        reported_user = db.users.find_one({"id": report_data.reported_user_id})
        reported_user_name = reported_user["name"] if reported_user else None

    reported_post_content = None
    if report_data.reported_post_id:
        rp = db.posts.find_one({"id": report_data.reported_post_id}, {"content": 1, "_id": 0})
        reported_post_content = (rp.get("content") if rp else None)

    report_dict = {
        "id": report_id,
        "reporter_id": current_user["id"],
        "reporter_name": current_user["name"],
        "reporter_email": current_user.get("email"),
        "reported_user_id": report_data.reported_user_id,
        "reported_user_name": reported_user_name,
        "reported_post_id": report_data.reported_post_id,
        "reported_post_content": reported_post_content,
        "reason": report_data.reason,
        "description": report_data.description or "",
        "status": "pending",
        "created_at": datetime.utcnow()
    }
    
    db.reports.insert_one(report_dict)
    return ReportResponse(**report_dict)

@api_router.get("/admin/reports", response_model=List[ReportResponse])
def get_reports_admin(status: Optional[str] = None, admin_user: dict = Depends(get_admin_user)):
    query = {}
    if status:
        query["status"] = status
    
    reports = list(db.reports.find(query).sort("created_at", -1).limit(200))
    return [ReportResponse(**report) for report in reports]

@api_router.put("/admin/reports/{report_id}")
def update_report_admin(report_id: str, status: str, admin_user: dict = Depends(get_admin_user)):
    report = db.reports.find_one({"id": report_id})
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    
    if status not in ["pending", "resolved", "dismissed"]:
        raise HTTPException(status_code=400, detail="Invalid status")
    
    db.reports.update_one({"id": report_id}, {"$set": {"status": status}})
    return {"message": "Report updated successfully"}

# Include the router
app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=[
        "https://peers.networth.ro",
        "https://www.peers.networth.ro",
        "http://localhost:8081",
    ],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Ensure indexes at startup (idempotent, non-fatal on failure)
ensure_indexes()

@app.on_event("shutdown")
def shutdown_db_client():
    client.close()
