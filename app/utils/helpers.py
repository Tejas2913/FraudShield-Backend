import json
import re


def sanitize_input(text: str, max_length: int = 5000) -> str:
    """Sanitize and truncate user input."""
    text = text.strip()[:max_length]
    # Remove null bytes
    text = text.replace("\x00", "")
    return text


def serialize_list(data: list) -> str:
    """Serialize a list to JSON string for DB storage."""
    return json.dumps(data, ensure_ascii=False)


def deserialize_list(data: str) -> list:
    """Deserialize JSON string from DB to list."""
    try:
        return json.loads(data) if data else []
    except (json.JSONDecodeError, TypeError):
        return []


def format_score(score: float) -> str:
    """Format a float score as a percentage string."""
    return f"{score:.1%}"


def is_valid_email(email: str) -> bool:
    pattern = r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$"
    return bool(re.match(pattern, email))
