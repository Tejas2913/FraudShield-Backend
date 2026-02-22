from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from datetime import datetime


class AnalyzeRequest(BaseModel):
    message: str = Field(..., min_length=5, max_length=5000, description="Suspicious message to analyze")


# ── Visualization sub-models ───────────────────────────────────────────────────
class WordImpact(BaseModel):
    word: str
    impact: float

class RiskMeterViz(BaseModel):
    score_percentage: float
    meter_color: str          # "red" | "orange" | "green"

class VisualizationBlock(BaseModel):
    risk_meter: RiskMeterViz
    feature_importance: List[WordImpact]
    highlighted_text: str     # HTML with <mark> tags


# ── Main response ──────────────────────────────────────────────────────────────
class AnalyzeResponse(BaseModel):
    # ── existing fields (unchanged) ──
    risk_level: str
    final_score: float
    rule_score: float
    ai_score: float
    scam_type: str
    matched_rules: List[str]
    suspicious_phrases: List[str]
    explanation: str
    scam_type_info: str
    safety_advice: List[str]
    analysis_id: Optional[int] = None
    # ── new visualization block ──
    visualization: Optional[VisualizationBlock] = None


# ── History & stats ──────────────────────────────────────────────────────────
class HistoryItem(BaseModel):
    id: int
    message: str
    risk_level: str
    final_score: float
    rule_score: float
    ai_score: float
    scam_type: str
    matched_rules: List[str]
    suspicious_phrases: List[str]
    created_at: datetime

    class Config:
        from_attributes = True


class StatsResponse(BaseModel):
    total_analyses: int
    risk_distribution: dict
    scam_type_distribution: dict
    daily_trend: List[dict]
    average_score: float
