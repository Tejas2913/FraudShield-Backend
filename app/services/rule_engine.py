import re
from typing import List, Dict

# ─── Suspicious context words ──────────────────────────────────────────────────
# OTP rule only triggers when these appear alongside "otp" — avoids false
# positives on legitimate delivery messages like "Your OTP is 123456. Don't share."
_OTP_CONTEXT_WORDS = {
    "share", "send", "give", "provide", "enter", "submit", "click",
    "verify", "confirm", "urgent", "immediately", "now", "asap",
    "block", "suspend", "deactivate", "arrest", "link", "login",
}

def _has_otp_scam_context(text_lower: str) -> bool:
    """Return True only when 'otp' co-occurs with a suspicious action word
    that is NOT preceded by a negation like 'do not', 'don't', 'never'."""
    if "otp" not in text_lower and "one time password" not in text_lower:
        return False
    # Strip negated phrases so "do not share" doesn't count as "share"
    cleaned = re.sub(
        r"(do\s+not|don'?t|never|not\s+to)\s+(\w+)",
        "",
        text_lower,
    )
    words = set(re.findall(r"\w+", cleaned))
    return bool(words & _OTP_CONTEXT_WORDS)


# ─── Rule definitions ──────────────────────────────────────────────────────────
# Each rule has:
#   name     – human-readable label shown in the UI
#   weight   – contribution to rule_score (weights sum to 1.0)
#   patterns – list of regex patterns; ONE match is enough to trigger
#   phrases  – hint phrases to surface in UI
#   context_fn – optional callable(text_lower)->bool for extra gating
# ──────────────────────────────────────────────────────────────────────────────
RULES: List[Dict] = [
    {
        "name": "OTP Request",
        "weight": 0.20,
        "patterns": [
            r"\botp\b",
            r"one[- ]time[- ]password",
            r"verification code",
        ],
        "phrases": ["OTP", "one time password", "verification code"],
        # Context gate: only trigger when combined with a suspicious action
        "context_fn": _has_otp_scam_context,
    },
    {
        "name": "Urgency / Threat",
        "weight": 0.18,
        "patterns": [
            r"\bimmediately\b",
            r"\burgent(ly)?\b",
            r"will be (blocked|suspended|deactivated|arrested|cancelled)",
            r"\blast warning\b",
            r"24 hours?",
            r"action will be taken",
        ],
        "phrases": ["immediately", "urgently", "will be blocked", "last warning"],
    },
    {
        "name": "Suspicious Link",
        "weight": 0.18,
        "patterns": [
            # Block suspicious short/unknown URLs but allow well-known domains
            r"https?://(?!(?:www\.)?(google|amazon|flipkart|irctc|sbi\.co|hdfcbank|icicibank|npci)\.(?:co\.in|com|in))\S+",
            r"bit\.ly",
            r"tinyurl",
            r"\bclick here\b",
            r"visit.*link",
            r"tap.*link",
        ],
        "phrases": ["click here", "suspicious URL", "short link"],
    },
    {
        "name": "Banking / UPI Impersonation",
        "weight": 0.20,
        "patterns": [
            r"\bkyc\b",
            r"account (blocked|frozen|suspended)",
            r"\bupi\b",
            r"\bifsc\b",
            r"net ?banking",
            r"debit card",
            r"credit card",
            r"bank account number",
        ],
        "phrases": ["KYC", "UPI", "bank account", "debit card"],
    },
    {
        "name": "Financial Reward / Lottery",
        "weight": 0.12,
        "patterns": [
            r"you (have |)won\b",
            r"lucky (winner|draw)",
            r"₹\s*[\d,]+",
            r"\d+ (lakh|thousand|crore)",
            r"\bprize\b",
            r"\bcashback\b(?!.*paytm|.*gpay|.*phonepe)",  # ignore legit CB promos
            r"\breward\b",
        ],
        "phrases": ["you won", "prize", "cashback", "reward"],
    },
    {
        "name": "Government / Legal Impersonation",
        "weight": 0.10,
        "patterns": [
            r"\bcbi\b",
            r"\bcid\b",
            r"\bpolice\b",
            r"income tax",
            r"supreme court",
            r"cyber crime",
            r"arrest warrant",
            r"fir (has been|will be) filed",
        ],
        "phrases": ["CBI", "income tax", "arrest warrant", "FIR"],
    },
    {
        "name": "Personal Info Request",
        "weight": 0.06,
        "patterns": [
            r"share (your )?(name|address|aadhaar|pan|dob|account)",
            r"confirm (your )?(details|account|identity)",
            r"provide (your )?(password|pin|cvv)",
            r"\baadhaar\b",
            r"\bpan\b",
        ],
        "phrases": ["Aadhaar", "PAN", "password", "PIN", "CVV"],
    },
]

_TOTAL_WEIGHT = sum(r["weight"] for r in RULES)


def analyze_rules(message: str) -> Dict:
    """
    Apply the contextual rule engine to the message.

    Returns:
        {
            "rule_score": float  (0.0 – 1.0, normalized),
            "matched_rules": List[str],
            "suspicious_phrases": List[str]
        }
    """
    text_lower = message.lower()
    matched_rules: List[str] = []
    suspicious_phrases: List[str] = []
    accumulated_score: float = 0.0

    for rule in RULES:
        # Optional extra context gate (e.g. for OTP)
        context_fn = rule.get("context_fn")
        if context_fn and not context_fn(text_lower):
            continue

        triggered = False
        for pattern in rule["patterns"]:
            m = re.search(pattern, text_lower)
            if m:
                triggered = True
                hit = m.group(0).strip()
                if len(hit) > 2:
                    suspicious_phrases.append(hit)
                break

        if triggered:
            matched_rules.append(rule["name"])
            accumulated_score += rule["weight"]
            # Add one representative phrase hint
            suspicious_phrases.extend(rule["phrases"][:1])

    # Normalize score to 0-1 range
    rule_score = min(accumulated_score / _TOTAL_WEIGHT, 1.0) if _TOTAL_WEIGHT else 0.0

    # Deduplicate while preserving order
    seen: set = set()
    unique_phrases: List[str] = []
    for p in suspicious_phrases:
        p = p.strip()
        if len(p) > 2 and p.lower() not in seen:
            seen.add(p.lower())
            unique_phrases.append(p)

    return {
        "rule_score": round(rule_score, 4),
        "matched_rules": matched_rules,
        "suspicious_phrases": unique_phrases[:10],
    }
