from sqlalchemy import Column, Integer, String, Float, DateTime, ForeignKey, Text
from sqlalchemy.orm import relationship
from datetime import datetime
from app.database.db import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), nullable=False)
    email = Column(String(150), unique=True, index=True, nullable=False)
    password_hash = Column(String(200), nullable=False)
    role = Column(String(20), default="user")
    created_at = Column(DateTime, default=datetime.utcnow)

    analyses = relationship("AnalyzedMessage", back_populates="user", cascade="all, delete-orphan")


class AnalyzedMessage(Base):
    __tablename__ = "analyzed_messages"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    message = Column(Text, nullable=False)
    rule_score = Column(Float, default=0.0)
    ai_score = Column(Float, default=0.0)
    final_score = Column(Float, default=0.0)
    risk_level = Column(String(20), default="LOW")
    scam_type = Column(String(100), default="Unknown")
    matched_rules = Column(Text, default="[]")
    suspicious_phrases = Column(Text, default="[]")
    explanation = Column(Text, default="")
    created_at = Column(DateTime, default=datetime.utcnow)

    user = relationship("User", back_populates="analyses")
