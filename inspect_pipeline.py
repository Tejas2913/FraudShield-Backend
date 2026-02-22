"""Inspect pipeline structure to determine correct input shape."""
import joblib
import pandas as pd
import numpy as np

m = joblib.load("app/models/model.pkl")
print("Pipeline type:", type(m).__name__)
print("Steps:")

for i, (name, step) in enumerate(m.steps):
    print(f"  [{i}] name='{name}'  type={type(step).__name__}")
    if hasattr(step, 'transformers'):
        for t_name, t_obj, t_cols in step.transformers:
            print(f"       transformer '{t_name}': cols={t_cols}  obj={type(t_obj).__name__}")
            if hasattr(t_obj, 'steps'):
                for sn, so in t_obj.steps:
                    extra = ""
                    if hasattr(so, 'vocabulary_'):
                        extra = f"  vocab_size={len(so.vocabulary_)}  has_idf={hasattr(so, 'idf_')}"
                    print(f"         sub-step '{sn}': {type(so).__name__}{extra}")
    if hasattr(step, 'estimators_'):
        for est in step.estimators_:
            print(f"       ensemble member: {type(est).__name__}")
    if hasattr(step, 'estimator'):
        print(f"       base estimator: {type(step.estimator).__name__}")

# Figure out what columns the pipeline needs
pre = m.steps[0][1]
if hasattr(pre, 'transformers'):
    print("\nRequired columns:")
    for t_name, t_obj, t_cols in pre.transformers:
        print(f"  {t_cols}")

# Try with a DataFrame
print("\nTrying DataFrame input...")
test_df = pd.DataFrame({
    "message": ["Your SBI account will be blocked. Share your OTP immediately."],
})
# Add common numeric columns that might be needed
for col in ["url_count", "digit_count", "rupee_count", "exclaim_count",
            "upper_word_count", "urgent_word_count",
            "num_urls", "has_phone", "has_otp", "message_length"]:
    test_df[col] = 0

try:
    proba = m.predict_proba(test_df)
    print("SUCCESS with DataFrame! proba =", proba[0])
except Exception as e:
    print("DataFrame FAILED:", e)

    # Try raw text
    print("\nTrying raw string list...")
    try:
        proba2 = m.predict_proba(["test message otp share"])
        print("SUCCESS with list! proba =", proba2[0])
    except Exception as e2:
        print("List also FAILED:", e2)
