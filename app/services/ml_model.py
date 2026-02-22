"""
ml_model.py — FraudShield AI ML inference layer
Loads the sklearn Pipeline (model.pkl) which contains:
  - ColumnTransformer preprocessor:
      • text  → ['clean_text']   → TfidfVectorizer(max_features=30000, ngram_range=(1,3), sublinear_tf=True)
      • num   → ['length','num_digits','num_exclaim','num_upper','num_urls','keyword_score','phishing_pattern'] → StandardScaler
  - VotingClassifier (Logistic Regression + SVM ensemble)

Input to predict_proba() must be a pandas DataFrame with ALL 8 columns above.
"""
import os
import re
import html
import joblib
import numpy as np
import pandas as pd
from typing import List, Dict

# ─── Constants ─────────────────────────────────────────────────────────────────
BEST_THRESHOLD = 0.4052312960713096  # calibrated threshold from notebook training

BASE_DIR   = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.abspath(os.path.join(BASE_DIR, "..", "models", "model.pkl"))

# Keyword list used for keyword_score feature (mirrors notebook)
_FRAUD_KEYWORDS = [
    "urgent", "immediately", "verify", "click", "otp", "kyc",
    "suspend", "block", "account", "password", "credentials",
    "bank", "upi", "won", "prize", "lottery", "free", "offer",
    "confirm", "update", "expires", "limited", "act now",
]

# Phishing-pattern signals used for phishing_pattern feature
_PHISHING_PATTERNS = [
    r"http[s]?://(?!(?:www\.)?(google|amazon|flipkart|irctc|sbi|hdfc|icici)\.)",
    r"bit\.ly",
    r"tinyurl",
    r"\bclick here\b",
    r"\bverify.*account\b",
    r"\blog.?in.*link\b",
]

# ─── Pipeline load ─────────────────────────────────────────────────────────────
try:
    _pipeline = joblib.load(MODEL_PATH)
    print(f"[FraudShield] ✅ Pipeline loaded : {MODEL_PATH}")
    print(f"[FraudShield] ✅ Best threshold  : {BEST_THRESHOLD}")
except Exception as e:
    raise RuntimeError(
        f"\n[FraudShield] FATAL: Cannot load model.pkl\n"
        f"  Path  : {MODEL_PATH}\n"
        f"  Error : {e}\n"
    ) from e


# ─── Feature engineering (must EXACTLY mirror notebook preprocessing) ──────────

def _clean_text(text: str) -> str:
    """Identical to the notebook's clean_text() function."""
    text = str(text).lower()
    text = re.sub(r"http\S+", " urltoken ", text)
    text = re.sub(r"\d+", " numtoken ", text)
    text = re.sub(r"[^\w\s]", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text


def _phishing_pattern(text: str) -> int:
    """Returns 1 if any phishing URL/link pattern is found."""
    text_lower = text.lower()
    for p in _PHISHING_PATTERNS:
        if re.search(p, text_lower):
            return 1
    return 0


def _keyword_score(text: str) -> int:
    """Count of fraud-related keywords present in text."""
    text_lower = text.lower()
    return sum(1 for kw in _FRAUD_KEYWORDS if kw in text_lower)


def _build_dataframe(text: str) -> pd.DataFrame:
    """
    Build the 8-column DataFrame expected by the pipeline's ColumnTransformer.
    Columns:
      clean_text, length, num_digits, num_exclaim, num_upper,
      num_urls, keyword_score, phishing_pattern
    """
    clean = _clean_text(text)
    return pd.DataFrame([{
        "clean_text":       clean,
        "length":           len(text),
        "num_digits":       len(re.findall(r"\d", text)),
        "num_exclaim":      text.count("!"),
        "num_upper":        sum(1 for w in text.split() if w.isupper()),
        "num_urls":         len(re.findall(r"http[s]?://\S+", text)),
        "keyword_score":    _keyword_score(text),
        "phishing_pattern": _phishing_pattern(text),
    }])


# ─── Feature importance extraction (TF-IDF + classifier coefficients) ─────────

def _get_contributing_words(text: str, top_n: int = 10) -> List[Dict]:
    """
    Extract the top-N words with highest impact on the fraud score.
    Works by accessing the TF-IDF step inside the ColumnTransformer.
    Falls back to an empty list if the pipeline structure can't be probed.
    """
    try:
        # Navigate into: pipeline → preprocessor (ColumnTransformer) → 'text' transformer
        pre = _pipeline.named_steps.get("preprocessor") or _pipeline.steps[0][1]
        tfidf = None
        for t_name, t_obj, t_cols in pre.transformers:
            if "clean_text" in (t_cols if isinstance(t_cols, list) else [t_cols]):
                # t_obj may be a bare TfidfVectorizer or a Pipeline with one
                tfidf = t_obj if hasattr(t_obj, "transform") else None
                break
        if tfidf is None:
            return []

        clean = _clean_text(text)
        tfidf_mat = tfidf.transform([clean])

        # Retrieve classifier coefficients (LR inside VotingClassifier)
        clf_step = _pipeline.steps[-1][1]
        coef = None
        if hasattr(clf_step, "estimators_"):
            for est in clf_step.estimators_:
                if hasattr(est, "coef_"):
                    coef = est.coef_[0]
                    break
        elif hasattr(clf_step, "coef_"):
            coef = clf_step.coef_[0]

        if coef is None:
            return []

        feature_names = np.array(tfidf.get_feature_names_out())
        present_idx = tfidf_mat.nonzero()[1]
        n_text_features = len(feature_names)

        # Only use coefficients for the TF-IDF feature range
        text_coef = coef[:n_text_features] if len(coef) > n_text_features else coef
        impacts = np.abs(text_coef[present_idx] * tfidf_mat[0, present_idx].toarray()[0])

        top_idx = np.argsort(impacts)[::-1][:top_n]
        return [
            {"word": str(feature_names[present_idx[i]]), "impact": round(float(impacts[i]), 4)}
            for i in top_idx
            if impacts[i] > 0
        ]
    except Exception:
        return []


# ─── Highlighted HTML generation ───────────────────────────────────────────────

def _build_highlighted_text(raw_text: str, contributing_words: List[Dict]) -> str:
    """Wrap top contributing words in <mark> tags for frontend rendering."""
    if not contributing_words:
        return html.escape(raw_text)
    top_words = sorted(
        [w["word"] for w in contributing_words[:8] if len(w["word"]) > 2],
        key=len, reverse=True,
    )
    escaped = html.escape(raw_text)
    for word in top_words:
        ew = html.escape(word)
        escaped = re.compile(re.escape(ew), re.IGNORECASE).sub(
            lambda m: f'<mark class="highlight-word">{m.group(0)}</mark>',
            escaped, count=5,
        )
    return escaped


# ─── Scam type detection (rule-based fallback) ────────────────────────────────

_SCAM_TYPE_MAP = {
    "OTP Fraud":                  [r"\botp\b", r"one[- ]time[- ]password"],
    "Banking / UPI Fraud":        [r"\bkyc\b", r"bank account", r"\bupi\b"],
    "Phishing":                   [r"https?://", r"\bclick here\b"],
    "Lottery / Prize Scam":       [r"\bwon\b", r"lucky winner", r"\bprize\b"],
    "Government Impersonation":   [r"\bcbi\b", r"income tax", r"arrest warrant"],
    "Job / Work-from-Home Scam":  [r"job offer", r"work from home"],
    "Courier Scam":               [r"\bparcel\b", r"\bcourier\b"],
}

def _detect_scam_type(text: str, scam_probability: float) -> str:
    # If ML says it's safe, always label as legitimate — no keyword override
    if scam_probability < BEST_THRESHOLD:
        return "Legitimate Message"
    text_lower = text.lower()
    for scam_type, patterns in _SCAM_TYPE_MAP.items():
        for p in patterns:
            if re.search(p, text_lower):
                return scam_type
    return "Fraudulent Message"


# ─── Public predict function ───────────────────────────────────────────────────

def predict(text: str) -> Dict:
    """
    Run full pipeline inference on a raw message string.

    Returns:
        {
            "scam_probability"  : float,
            "scam_type"         : str,
            "contributing_words": [{"word": str, "impact": float}, ...],
            "highlighted_text"  : str  (safe HTML),
        }
    """
    df = _build_dataframe(text)
    scam_probability = float(_pipeline.predict_proba(df)[0][1])
    scam_type = _detect_scam_type(text, scam_probability)
    contributing_words = _get_contributing_words(text)
    highlighted_text = _build_highlighted_text(text, contributing_words)

    return {
        "scam_probability":   round(scam_probability, 4),
        "scam_type":          scam_type,
        "contributing_words": contributing_words,
        "highlighted_text":   highlighted_text,
    }