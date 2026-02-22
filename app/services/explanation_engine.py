from typing import List, Dict

# ─── Per-rule human-readable fragments ────────────────────────────────────────
_RULE_EXPLANATIONS = {
    "OTP Request":                    "requests your one-time password (OTP) in a suspicious context — legitimate services never ask you to share an OTP",
    "Urgency / Threat":               "creates artificial urgency or threatens consequences to pressure you into acting without thinking",
    "Suspicious Link":                "contains a suspicious or shortened URL that may redirect to a phishing website",
    "Banking / UPI Impersonation":    "impersonates a bank, UPI service, or financial institution to steal credentials",
    "Financial Reward / Lottery":     "promises financial rewards or lottery winnings — a classic social-engineering tactic",
    "Government / Legal Impersonation": "falsely claims to be from a government agency or legal authority to intimidate the recipient",
    "Personal Info Request":          "requests sensitive personal information such as Aadhaar, PAN, or account details",
}

# ─── Safety advice per risk level ─────────────────────────────────────────────
_SAFETY_ADVICE = {
    "HIGH": [
        "🚫 Do NOT respond to this message under any circumstances.",
        "🔐 Never share OTPs, passwords, PINs, or banking credentials with anyone.",
        "📞 If it claims to be your bank, call the official number on the back of your card.",
        "🗑️ Delete this message and block the sender immediately.",
        "📲 Report to the Cyber Crime Helpline: 1930 or cybercrime.gov.in",
    ],
    "MEDIUM": [
        "⚠️ Be cautious — this message shows suspicious characteristics and should be treated carefully.",
        "🔍 Verify the sender's identity through official channels before taking any action.",
        "🔗 Do not click any links without first checking the full URL.",
        "📞 Contact the organisation directly using their official website or helpline.",
        "🧠 Take your time — legitimate organisations never demand immediate action.",
    ],
    "LOW": [
        "✅ This message contains limited risk indicators and appears relatively safe.",
        "🔍 Always stay vigilant — even legitimate-looking messages can occasionally be spoofed.",
        "🔗 Verify any links before clicking, especially if they ask you to log in.",
        "📞 When in doubt, confirm with the sender through an official channel.",
    ],
}

# ─── Scam-type educational descriptions ───────────────────────────────────────
_SCAM_TYPE_INFO = {
    "OTP Fraud":                  "OTP fraud is one of the most common scam types in India. Fraudsters pose as bank representatives or government officials to steal your OTP and drain your accounts.",
    "Banking / UPI Fraud":        "Banking fraud involves criminals impersonating your bank to steal KYC details, account numbers, or UPI credentials.",
    "Banking Fraud":              "Banking fraud involves criminals impersonating your bank to steal KYC details, account numbers, or UPI credentials.",
    "Phishing":                   "Phishing attacks use fake links to redirect you to counterfeit websites that steal login credentials or financial information.",
    "Lottery / Prize Scam":       "Lottery scams promise fake winnings to trick victims into paying 'processing fees' or sharing personal details.",
    "Lottery Scam":               "Lottery scams promise fake winnings to trick victims into paying 'processing fees' or sharing personal details.",
    "Government Impersonation":   "Scammers impersonate CBI, income tax, or police officers to threaten victims into making payments or sharing personal data.",
    "Job / Work-from-Home Scam":  "Job scams offer fake employment opportunities to extract registration fees or personal information.",
    "Job Scam":                   "Job scams offer fake employment opportunities to extract registration fees or personal information.",
    "Courier Scam":               "Courier scams claim your parcel is held at customs and demand payment of fake fees to release it.",
    "General Scam":               "This message exhibits general fraud patterns. Exercise caution before taking any action.",
}


def generate_explanation(
    matched_rules: List[str],
    scam_type: str,
    risk_level: str,
    final_score: float,
    scam_probability: float,
) -> Dict:
    """
    Generate a risk-level-aware, human-readable explanation and safety advice.

    The explanation language is calibrated to the risk_level:
      HIGH   → strong warning language
      MEDIUM → cautious language
      LOW    → balanced / informational language

    Returns:
        {
            "explanation": str,
            "scam_type_info": str,
            "safety_advice": List[str]
        }
    """
    score_pct = f"{scam_probability:.0%}"
    total_pct = f"{final_score:.0%}"

    if risk_level == "HIGH":
        if matched_rules:
            rule_parts = [_RULE_EXPLANATIONS.get(r, r.lower()) for r in matched_rules]
            if len(rule_parts) == 1:
                rules_str = rule_parts[0]
            elif len(rule_parts) == 2:
                rules_str = f"{rule_parts[0]} and {rule_parts[1]}"
            else:
                rules_str = ", ".join(rule_parts[:-1]) + f", and {rule_parts[-1]}"
            explanation = (
                f"⚠️ HIGH RISK: This message {rules_str}. "
                f"The AI model assigned a fraud confidence of {score_pct}, "
                f"resulting in an overall risk score of {total_pct}. "
                f"This is very likely a scam — do not engage."
            )
        else:
            explanation = (
                f"⚠️ HIGH RISK: The AI model assigned a fraud confidence of {score_pct}. "
                f"Although no specific rule patterns were triggered, the overall message "
                f"structure strongly resembles known fraudulent communications. "
                f"Do not respond or share any personal information."
            )

    elif risk_level == "MEDIUM":
        if matched_rules:
            rules_str = ", ".join(matched_rules)
            explanation = (
                f"⚠️ MEDIUM RISK: This message shows suspicious characteristics and should be treated carefully. "
                f"The following patterns were detected: {rules_str}. "
                f"The AI confidence is {score_pct} with an overall risk score of {total_pct}. "
                f"Verify the sender before taking any action."
            )
        else:
            explanation = (
                f"⚠️ MEDIUM RISK: This message shows suspicious characteristics based on the AI model "
                f"(confidence: {score_pct}, risk score: {total_pct}). "
                f"No specific rule patterns were triggered, but treat this message carefully "
                f"and verify the sender's identity before responding."
            )

    else:  # LOW
        if matched_rules:
            rules_str = ", ".join(matched_rules)
            explanation = (
                f"ℹ️ LOW RISK: This message contains limited risk indicators. "
                f"The following mild patterns were noted: {rules_str}. "
                f"The AI model assigned a fraud confidence of only {score_pct} "
                f"(risk score: {total_pct}). "
                f"The message is likely safe, but always remain vigilant."
            )
        else:
            explanation = (
                f"✅ LOW RISK: This message appears safe. "
                f"No suspicious rule patterns were detected and the AI model assigned "
                f"a low fraud confidence of {score_pct} (risk score: {total_pct}). "
                f"Always stay cautious with unsolicited messages."
            )

    return {
        "explanation":    explanation,
        "scam_type_info": _SCAM_TYPE_INFO.get(scam_type, _SCAM_TYPE_INFO["General Scam"]),
        "safety_advice":  _SAFETY_ADVICE.get(risk_level, _SAFETY_ADVICE["LOW"]),
    }
