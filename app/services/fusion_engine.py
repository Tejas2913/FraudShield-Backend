from typing import Dict


def fuse_scores(rule_score: float, scam_probability: float) -> Dict:
    """
    Hybrid fusion engine.

    Fast-path: if ML is very confident (≥ 0.75) → immediately HIGH,
    regardless of rule score. This prevents low-rule messages from
    being under-classified when the model is highly confident.

    Otherwise: weighted blend where ML is the primary driver.
        final_score = 0.7 × scam_probability + 0.3 × rule_score

    Risk thresholds:
        >= 0.60 → HIGH
        >= 0.35 → MEDIUM
        <  0.35 → LOW
    """
    if scam_probability >= 0.75:
        # High ML confidence → skip blend, go straight to HIGH
        final_score = round((0.7 * scam_probability) + (0.3 * rule_score), 4)
        risk_level = "HIGH"
    else:
        final_score = round((0.7 * scam_probability) + (0.3 * rule_score), 4)
        if final_score >= 0.60:
            risk_level = "HIGH"
        elif final_score >= 0.35:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"

    return {
        "final_score": final_score,
        "risk_level":  risk_level,
    }