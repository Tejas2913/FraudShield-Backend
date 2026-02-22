"""End-to-end predict test."""
import sys, os
os.environ["PYTHONIOENCODING"] = "utf-8"
sys.path.insert(0, ".")

print("--- Loading ml_model ---")
from app.services.ml_model import predict

tests = [
    ("SCAM_OTP",  "Your SBI account will be blocked. Share your OTP immediately to avoid arrest."),
    ("PHISHING",  "Click http://bit.ly/fakelink to verify KYC or account suspended in 24 hours."),
    ("LEGIT_OTP", "Your OTP for login is 482931. Do not share this OTP with anyone."),
    ("SAFE",      "Your Amazon order has been shipped. Track it at amazon.in."),
]

for label, msg in tests:
    try:
        r = predict(msg)
        print(f"[{label}]")
        print(f"  scam_probability = {r['scam_probability']}")
        print(f"  scam_type        = {r['scam_type']}")
        cw = r.get("contributing_words", [])
        print(f"  contributing_words ({len(cw)}) = {[w['word'] for w in cw[:5]]}")
        print(f"  highlighted_text  = {r['highlighted_text'][:80]}...")
        print()
    except Exception as e:
        print(f"[{label}] FAILED: {e}")
        import traceback; traceback.print_exc()
        print()

print("--- Testing fusion + rules ---")
from app.services.rule_engine import analyze_rules
from app.services.fusion_engine import fuse_scores

msg = "Your SBI account will be blocked. Share your OTP immediately to avoid arrest."
rules = analyze_rules(msg)
ml = predict(msg)
fusion = fuse_scores(rules["rule_score"], ml["scam_probability"])
print(f"  rule_score = {rules['rule_score']}")
print(f"  ai_score   = {ml['scam_probability']}")
print(f"  final_score= {fusion['final_score']}")
print(f"  risk_level = {fusion['risk_level']}")
print(f"  matched    = {rules['matched_rules']}")
print()
print("=== ALL TESTS DONE ===")
