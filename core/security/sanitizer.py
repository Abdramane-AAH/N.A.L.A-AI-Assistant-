import re
from typing import Any, Union

class DataSanitizer:
    # Patterns regex that needed to be sanitized in the data
    PATTERNS = {
        "JWT/Bearer Token": r"(?i)bearer\s+[a-zA-Z0-9_\-\.]+",
        "Discord Token": r"[\w-]{24,26}\.[\w-]{6}\.[\w-]{27,38}",
        "Generic Secret/Key": r"(?i)(key|secret|token|password|auth|pwd)\s*[:=]\s*['\"]?([a-zA-Z0-9_\-\.]{8,})['\"]?",
        "Windows Absolute Path": r"[A-Za-z]:\\(?:[^\\/:*?\"<>|\r\n]+\\)*[^\\/:*?\"<>|\r\n]*",
        "Unix Home Path": r"/(?:home|Users)/[a-zA-Z0-9_\-]+(?:/[a-zA-Z0-9_\-\.]+)*",
    }

    @classmethod
    def sanitize_text(cls, text: str) -> str:
        """Clean sensitive information from a string based on predefined patterns"""
        if not isinstance(text, str):
            return text

        sanitized = text
        for label, pattern in cls.PATTERNS.items():
            if "Secret/Key" in label:
                # keep the key name but redact the value
                sanitized = re.sub(
                    pattern,
                    r"\1=[REDACTED]",
                    sanitized
                )
            else:
                sanitized = re.sub(pattern, "[REDACTED]", sanitized)
        return sanitized

    @classmethod
    def sanitize_data(cls, data: Union[dict, list, str, Any]) -> Any:
        """Clean sensitive information from complex data structures"""
        if isinstance(data, str):
            return cls.sanitize_text(data)
        elif isinstance(data, dict):
            return {k: cls.sanitize_data(v) for k, v in data.items()}
        elif isinstance(data, list):
            return [cls.sanitize_data(item) for item in data]
        return data