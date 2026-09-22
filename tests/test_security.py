import pytest
from pathlib import Path
from config.settings import Settings
from core.security.sanitizer import DataSanitizer

def test_settings_default_values():
    test_settings = Settings()
    assert test_settings.LLM_MODEL_NAME == "llama3.2:3b"
    assert test_settings.OLLAMA_BASE_URL == "http://127.0.0.1:11434"
    assert isinstance(test_settings.EXECUTION_SANDBOX_PATH, Path)

def test_sanitize_bearer_token():
    raw_input = "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.dummy_token"
    sanitized = DataSanitizer.sanitize_text(raw_input)
    assert "Bearer [REDACTED]" in sanitized
    assert "eyJhbGciOi" not in sanitized

def test_sanitize_discord_token():
    raw_input = "User token is sampledummytokenformat123.abcdef.dummysecretpayloadkeyformat987654"
    sanitized = DataSanitizer.sanitize_text(raw_input)
    assert "[REDACTED]" in sanitized
    assert "sampledummytokenformat123" not in sanitized

def test_sanitize_generic_secrets():
    cases = [
        ("api_key='SuperSecretKey12345'", "api_key='[REDACTED]'"),
        ('password: "MySecurePassword2026"', 'password: "[REDACTED]"'),
        ("token = abcdefgh12345678", "token = [REDACTED]"),
    ]
    for raw_case, expected in cases:
        sanitized = DataSanitizer.sanitize_text(raw_case)
        assert sanitized == expected
        assert "SuperSecretKey12345" not in sanitized
        assert "MySecurePassword2026" not in sanitized

def test_sanitize_system_paths():
    windows_path = r"Error loading file C:\Users\Admin\Documents\secret_project\main.py"
    unix_path = "Log path: /home/developer/workspace/app.log"
    
    assert "[REDACTED]" in DataSanitizer.sanitize_text(windows_path)
    assert "C:\\Users\\Admin" not in DataSanitizer.sanitize_text(windows_path)
    assert "[REDACTED]" in DataSanitizer.sanitize_text(unix_path)
    assert "/home/developer" not in DataSanitizer.sanitize_text(unix_path)

def test_sanitize_complex_nested_data():
    payload = {
        "user": "Sangoku",
        "env": {
            "token": "secret_token_12345678",
            "debug": True
        },
        "paths": [
            r"D:\Data\config.json",
            "/home/user/file.txt"
        ]
    }
    cleaned = DataSanitizer.sanitize_data(payload)
    assert cleaned["user"] == "Sangoku"
    assert cleaned["env"]["token"] == "[REDACTED]"
    assert cleaned["env"]["debug"] is True
    assert "[REDACTED]" in cleaned["paths"][0]
    assert "[REDACTED]" in cleaned["paths"][1]