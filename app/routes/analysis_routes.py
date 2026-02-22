from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.database.db import get_db
from app.database.models import User, AnalyzedMessage
from app.middleware.auth_middleware import get_current_user
from app.schemas.analysis_schemas import (
    AnalyzeRequest, AnalyzeResponse,
    HistoryItem, VisualizationBlock, RiskMeterViz, WordImpact,
)
from app.services import ml_model, rule_engine, fusion_engine, explanation_engine
from app.utils.helpers import sanitize_input, serialize_list, deserialize_list

router = APIRouter(prefix="/api", tags=["Analysis"])


def _build_visualization(
    final_score: float,
    risk_level: str,
    contributing_words: list,
    highlighted_text: str,
) -> VisualizationBlock:
    """Build the visualization block from computed analysis results."""
    color_map = {"HIGH": "red", "MEDIUM": "orange", "LOW": "green"}
    return VisualizationBlock(
        risk_meter=RiskMeterViz(
            score_percentage=round(final_score * 100, 1),
            meter_color=color_map.get(risk_level, "green"),
        ),
        feature_importance=[
            WordImpact(word=w["word"], impact=w["impact"])
            for w in contributing_words
        ],
        highlighted_text=highlighted_text,
    )


@router.post("/analyze", response_model=AnalyzeResponse)
def analyze_message(
    payload: AnalyzeRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    message = sanitize_input(payload.message)

    # ── Step 1: Rule-based analysis
    rule_result = rule_engine.analyze_rules(message)

    # ── Step 2: ML prediction (Pipeline inference + feature importance)
    ml_result = ml_model.predict(message)

    # ── Step 3: Fuse scores → final_score + risk_level
    fusion_result = fusion_engine.fuse_scores(
        rule_score=rule_result["rule_score"],
        scam_probability=ml_result["scam_probability"],
    )

    # ── Step 4: Human-readable explanation (risk-level aware)
    explanation_result = explanation_engine.generate_explanation(
        matched_rules=rule_result["matched_rules"],
        scam_type=ml_result["scam_type"],
        risk_level=fusion_result["risk_level"],
        final_score=fusion_result["final_score"],
        scam_probability=ml_result["scam_probability"],
    )

    # ── Step 5: Build visualization block
    viz = _build_visualization(
        final_score=fusion_result["final_score"],
        risk_level=fusion_result["risk_level"],
        contributing_words=ml_result.get("contributing_words", []),
        highlighted_text=ml_result.get("highlighted_text", message),
    )

    # ── Step 6: Persist to DB
    record = AnalyzedMessage(
        user_id=current_user.id,
        message=message,
        rule_score=rule_result["rule_score"],
        ai_score=ml_result["scam_probability"],
        final_score=fusion_result["final_score"],
        risk_level=fusion_result["risk_level"],
        scam_type=ml_result["scam_type"],
        matched_rules=serialize_list(rule_result["matched_rules"]),
        suspicious_phrases=serialize_list(rule_result["suspicious_phrases"]),
        explanation=explanation_result["explanation"],
    )
    db.add(record)
    db.commit()
    db.refresh(record)

    return AnalyzeResponse(
        # ── preserved existing fields ──
        risk_level=fusion_result["risk_level"],
        final_score=fusion_result["final_score"],
        rule_score=rule_result["rule_score"],
        ai_score=ml_result["scam_probability"],
        scam_type=ml_result["scam_type"],
        matched_rules=rule_result["matched_rules"],
        suspicious_phrases=rule_result["suspicious_phrases"],
        explanation=explanation_result["explanation"],
        scam_type_info=explanation_result["scam_type_info"],
        safety_advice=explanation_result["safety_advice"],
        analysis_id=record.id,
        # ── new visualization block ──
        visualization=viz,
    )


@router.get("/history", response_model=list[HistoryItem])
def get_history(
    skip: int = 0,
    limit: int = 20,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    records = (
        db.query(AnalyzedMessage)
        .filter(AnalyzedMessage.user_id == current_user.id)
        .order_by(AnalyzedMessage.created_at.desc())
        .offset(skip)
        .limit(limit)
        .all()
    )

    return [
        HistoryItem(
            id=r.id,
            message=r.message[:200] + ("..." if len(r.message) > 200 else ""),
            risk_level=r.risk_level,
            final_score=r.final_score,
            rule_score=r.rule_score,
            ai_score=r.ai_score,
            scam_type=r.scam_type,
            matched_rules=deserialize_list(r.matched_rules),
            suspicious_phrases=deserialize_list(r.suspicious_phrases),
            created_at=r.created_at,
        )
        for r in records
    ]
