"""Diagnose model loading error."""
import traceback
import sys
import os

os.chdir(r"c:\Users\hp\Desktop\FraudShield AI\backend")
sys.path.insert(0, ".")

# Test 1: Raw joblib load
print("=== Test 1: joblib.load ===")
try:
    import joblib
    m = joblib.load("app/models/model.pkl")
    print("OK - type:", type(m).__name__)
except Exception as e:
    print("FAIL:", str(e)[:200])
    traceback.print_exc()

# Test 2: pickle load with open(rb)
print("\n=== Test 2: pickle.load ===")
try:
    import pickle
    with open("app/models/model.pkl", "rb") as f:
        m2 = pickle.load(f)
    print("OK - type:", type(m2).__name__)
except Exception as e:
    print("FAIL:", str(e)[:200])

# Test 3: joblib version
print("\n=== Versions ===")
print("joblib:", joblib.__version__)
import sklearn
print("sklearn:", sklearn.__version__)
print("python:", sys.version)
