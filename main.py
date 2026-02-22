import sys
import os

# Ensure the backend/app directory is importable
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.database.db import engine
from app.database import models as db_models
from app.routes import auth_routes, analysis_routes, dashboard_routes

# Create all tables
db_models.Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="FraudShield AI API",
    description="Real-Time Digital Scam Detection & Awareness Platform",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# CORS – allow all localhost origins (covers port shifts in dev)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://localhost:5174",
        "http://localhost:5175",
        "http://localhost:3000",
        "http://127.0.0.1:5173",
        "http://127.0.0.1:5174",
        "http://127.0.0.1:5175",
        "http://127.0.0.1:3000",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register routers
app.include_router(auth_routes.router)
app.include_router(analysis_routes.router)
app.include_router(dashboard_routes.router)


@app.get("/", tags=["Health"])
def root():
    return {
        "service": "FraudShield AI",
        "status": "online",
        "version": "1.0.0",
        "docs": "/docs",
    }


@app.get("/health", tags=["Health"])
def health():
    return {"status": "healthy"}
