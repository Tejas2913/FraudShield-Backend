"""
Quick diagnostic – run from backend/ with:
  .\venv\Scripts\python.exe test_pipeline_check.py
"""
import sys
sys.path.insert(0, ".")
errors = []

# 1. Schemas
try:
    from app.schemas.analysis_schemas import AnalyzeResponse, VisualizationBlock, RiskMeterViz, WordImpact
    print("[OK] analysis_schemas.py – VisualizationBlock + sub-models imported")
except Exception as e:
    errors.append(f"[FAIL] analysis_schemas: {e}")

# 2. Fusion engine
try:
    from app.services.fusion_engine import fuse_scores
    r_high  = fuse_scores(rule_score=0.3, scam_probability=0.8)
    r_low   = fuse_scores(rule_score=0.0, scam_probability=0.1)
    r_med   = fuse_scores(rule_score=0.5, scam_probability=0.45)
    assert r_high["risk_level"] == "HIGH", r_high
    assert r_low["risk_level"] == "LOW",   r_low
    print(f"  HIGH case : {r_high}")
    print(f"  LOW  case : {r_low}")
    print(f"  MED  case : {r_med}")
    print("[OK] fusion_engine.py")
except Exception as e:
    errors.append(f"[FAIL] fusion_engine: {e}")

# 3. Rule engine – OTP context gate
try:
    from app.services.rule_engine import analyze_rules
    legit = analyze_rules("Your OTP for login is 482931. Do not share this OTP.")
    scam  = analyze_rules("Your SBI account will be blocked. Share your OTP immediately.")
    print(f"  Legit OTP – rules={legit['matched_rules']}  score={legit['rule_score']}")
    print(f"  Scam OTP  – rules={scam['matched_rules']}  score={scam['rule_score']}")
    if "OTP Request" in legit["matched_rules"]:
        errors.append("[FAIL] rule_engine: Legit OTP message SHOULD NOT trigger OTP rule")
    if "OTP Request" not in scam["matched_rules"]:
        errors.append("[FAIL] rule_engine: Scam OTP message SHOULD trigger OTP rule")
    else:
        print("[OK] rule_engine.py – OTP context gate working correctly")
except Exception as e:
    errors.append(f"[FAIL] rule_engine: {e}")

# 4. ML model – Pipeline load + predict
try:
    from app.services.ml_model import predict, BEST_THRESHOLD
    print(f"  BEST_THRESHOLD = {BEST_THRESHOLD}")
    msg = "Your SBI account will be blocked. Share your OTP immediately to avoid arrest."
    result = predict(msg)
    print(f"  scam_probability = {result['scam_probability']}")
    print(f"  scam_type        = {result['scam_type']}")
    print(f"  contributing_words (top 3) = {result['contributing_words'][:3]}")
    print(f"  highlighted_text snippet = {result['highlighted_text'][:80]!r}")
    print("[OK] ml_model.py – Pipeline loads, predict() returns enriched result")
except Exception as e:
    errors.append(f"[FAIL] ml_model: {e}")

# Summary
print()
if errors:
    for err in errors:
        print(err)
    sys.exit(1)
else:
    print("=== All checks passed. Backend is ready to restart. ===")
