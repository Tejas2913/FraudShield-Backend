"""Extract exact pipeline structure and write concise JSON."""
import joblib, json

m = joblib.load("app/models/model.pkl")
pre = m.steps[0][1]

result = {}
for t_name, t_obj, t_cols in pre.transformers:
    result[t_name] = {
        "cols": t_cols if isinstance(t_cols, list) else [t_cols],
        "type": type(t_obj).__name__
    }

with open("cols.json", "w") as f:
    json.dump(result, f, indent=2, default=str)

print("done")
