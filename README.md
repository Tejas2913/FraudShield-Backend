# FraudShield AI – Full System Overview

FraudShield AI is a Real-Time Digital Scam Detection & Awareness Platform built using a full-stack architecture and a machine learning pipeline. The system consists of three main components: a FastAPI backend, a React frontend, and a research repository containing model training and experimentation notebooks.

================================================================================

# FraudShield AI – Backend

The backend powers authentication, scam analysis, user management, and ML inference using FastAPI and a trained Scikit-learn model.

## Live API
Production URL:
https://fraudshield-backend-6.onrender.com

API Docs (Swagger):
https://fraudshield-backend-6.onrender.com/docs

## Features
- JWT-based Authentication (Signup/Login)
- Secure password hashing with bcrypt
- ML-powered scam prediction
- SQLAlchemy ORM integration
- SQLite database (upgradeable to PostgreSQL)
- Production deployment via Render
- RESTful API architecture

## Tech Stack
- FastAPI
- SQLAlchemy
- SQLite
- python-jose (JWT)
- bcrypt
- Scikit-learn
- Gunicorn
- Uvicorn
- Render (Deployment)

## Project Structure
app/
├── database/
├── routes/
├── schemas/
├── middleware/
├── models/
│   └── model.pkl
main.py
requirements.txt

## Authentication Endpoints
- POST /auth/signup
- POST /auth/login
- GET /auth/me
- POST /auth/logout

JWT tokens are issued during signup and login.

## ML Integration
- Model trained using Scikit-learn
- Saved as model.pkl
- Loaded during backend startup
- Used for scam detection via prediction endpoints

## Environment Variables
- DATABASE_URL=sqlite:///./fraudshield.db
- SECRET_KEY=your_secret_key
- ALGORITHM=HS256
- ACCESS_TOKEN_EXPIRE_MINUTES=60

## Local Development
- pip install -r requirements.txt
- uvicorn main:app --reload

## Production Deployment
### Build Command:
- pip install -r requirements.txt

### Start Command:
- gunicorn main:app -k uvicorn.workers.UvicornWorker --bind 0.0.0.0:$PORT

