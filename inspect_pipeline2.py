"""Inspect pipeline and write structure to JSON."""
import joblib, json, sys

m = joblib.load("app/models/model.pkl")
info = {"steps": []}

for step_name, step_obj in m.steps:
    entry = {"name": step_name, "type": type(step_obj).__name__}
    if hasattr(step_obj, "transformers"):
        entry["transformers"] = []
        for t_name, t_obj, t_cols in step_obj.transformers:
            t_entry = {"name": t_name, "cols": list(t_cols) if not isinstance(t_cols, str) else t_cols, "type": type(t_obj).__name__}
            if hasattr(t_obj, "steps"):
                t_entry["sub_steps"] = []
                for sn, so in t_obj.steps:
                    se = {"name": sn, "type": type(so).__name__}
                    if hasattr(so, "vocabulary_"):
                        se["vocab_size"] = len(so.vocabulary_)
                        se["has_idf"] = hasattr(so, "idf_")
                        se["sample_features"] = list(so.get_feature_names_out())[:10]
                    t_entry["sub_steps"].append(se)
            entry["transformers"].append(t_entry)
    if hasattr(step_obj, "estimators_"):
        entry["estimators"] = [type(e).__name__ for e in step_obj.estimators_]
    if hasattr(step_obj, "coef_"):
        entry["coef_shape"] = list(step_obj.coef_.shape)
    info["steps"].append(entry)

with open("pipeline_structure.json", "w") as f:
    json.dump(info, f, indent=2, default=str)

print("Written pipeline_structure.json")

# Also try to call predict_proba with a DataFrame immediately
import pandas as pd
import numpy as np

# Get column names from the ColumnTransformer
pre = m.steps[0][1]
all_cols = []
if hasattr(pre, "transformers"):
    for t_name, t_obj, t_cols in pre.transformers:
        if isinstance(t_cols, list):
            all_cols.extend(t_cols)
        elif isinstance(t_cols, str):
            all_cols.append(t_cols)

info["all_expected_columns"] = all_cols
with open("pipeline_structure.json", "w") as f:
    json.dump(info, f, indent=2, default=str)

print("All expected columns:", all_cols)

# Build test DataFrame with those columns and try predict
row = {col: ("test otp share urgent blocked" if col in ("message", "text", "sms", "content") else 0) for col in all_cols}
test_df = pd.DataFrame([row])
try:
    p = m.predict_proba(test_df)
    print("predict_proba SUCCEEDED:", p[0])
except Exception as e:
    print("predict_proba FAILED:", str(e)[:200])
