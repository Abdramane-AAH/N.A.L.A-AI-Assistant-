import re
from typing import Any, Union

class DataSanitizer:
    # Patterns regex that needed to be sanitized in the data
    SENSITIVE_KEY_NAMES = {"key", "secret", "token", "password", "auth", "pwd", "api_key"}

    PATTERNS = {
        "Bearer Token": (r"(?i)(bearer\s+)[a-zA-Z0-9_\-\.]+", r"\1[REDACTED]"),
        "Discord Token": (r"[\w-]{24,26}\.[\w-]{6}\.[\w-]{27,38}", "[REDACTED]"),
        "Generic Secret": (r"(?i)((?:key|secret|token|password|auth|pwd)\s*[:=]\s*['\"]?)([a-zA-Z0-9_\-\.]{8,})(['\"]?)", r"\1[REDACTED]\3"),
        "Windows Path": (r"[A-Za-z]:\\(?:[^\\/:*?\"<>|\r\n]+\\)*[^\\/:*?\"<>|\r\n]*", "[REDACTED]"),
        "Unix Home Path": (r"/(?:home|Users)/[a-zA-Z0-9_\-]+(?:/[a-zA-Z0-9_\-\.]+)*", "[REDACTED]"),
    }

    @classmethod
    def sanitize_text(cls, text: str) -> str:
        """Clean sensitive information from a string based on predefined patterns"""
        if not isinstance(text, str):
            return text

        sanitized = text
        for _, (pattern, replacement) in cls.PATTERNS.items():
            sanitized = re.sub(pattern, replacement, sanitized)
        return sanitized

    @classmethod
    def sanitize_data(cls, data: Union[dict, list, str, Any]) -> Any:
        """Clean sensitive information from complex data structures"""
        if isinstance(data, str):
            return cls.sanitize_text(data)
        elif isinstance(data, dict):
            cleaned_dict = {}
            for k, v in data.items():
                if any(sensitive in str(k).lower() for sensitive in cls.SENSITIVE_KEY_NAMES) and isinstance(v, str):
                    cleaned_dict[k] = "[REDACTED]"
                else:
                    cleaned_dict[k] = cls.sanitize_data(v)
            return cleaned_dict
        elif isinstance(data, list):
            return [cls.sanitize_data(item) for item in data]
        return data