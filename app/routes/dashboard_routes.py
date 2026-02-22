from datetime import datetime, timedelta
from collections import defaultdict
import json

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func

from app.database.db import get_db
from app.database.models import User, AnalyzedMessage
from app.middleware.auth_middleware import get_current_user
from app.schemas.analysis_schemas import StatsResponse

router = APIRouter(prefix="/api", tags=["Dashboard"])


@router.get("/stats", response_model=StatsResponse)
def get_stats(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    records = (
        db.query(AnalyzedMessage)
        .filter(AnalyzedMessage.user_id == current_user.id)
        .all()
    )

    total = len(records)
    if total == 0:
        return StatsResponse(
            total_analyses=0,
            risk_distribution={"LOW": 0, "MEDIUM": 0, "HIGH": 0},
            scam_type_distribution={},
            daily_trend=[],
            average_score=0.0,
        )

    # Risk distribution
    risk_dist = defaultdict(int)
    scam_dist = defaultdict(int)
    daily: dict = defaultdict(list)
    total_score = 0.0

    for r in records:
        risk_dist[r.risk_level] += 1
        scam_dist[r.scam_type] += 1
        day_key = r.created_at.strftime("%Y-%m-%d")
        daily[day_key].append(r.final_score)
        total_score += r.final_score

    # Daily trend: last 14 days
    daily_trend = []
    today = datetime.utcnow().date()
    for i in range(13, -1, -1):
        day = (today - timedelta(days=i)).strftime("%Y-%m-%d")
        scores = daily.get(day, [])
        daily_trend.append({
            "date": day,
            "count": len(scores),
            "avg_score": round(sum(scores) / len(scores), 3) if scores else 0.0,
        })

    return StatsResponse(
        total_analyses=total,
        risk_distribution=dict(risk_dist),
        scam_type_distribution=dict(scam_dist),
        daily_trend=daily_trend,
        average_score=round(total_score / total, 4),
    )
