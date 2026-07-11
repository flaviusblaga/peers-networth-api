# Peers by NetWorth - Backend API

FastAPI + MongoDB Atlas backend for Peers by NetWorth professional networking app.

## Deploy on Render.com

1. Fork/import this repo
2. New → Web Service → connect this repo
3. Runtime: Python 3.11
4. Build: `pip install -r requirements.txt`
5. Start: `uvicorn server:app --host 0.0.0.0 --port $PORT`
6. Environment variables:
   - `MONGO_URL` - MongoDB Atlas connection string
   - `DB_NAME` - networth_db
   - `SECRET_KEY` - JWT signing key
