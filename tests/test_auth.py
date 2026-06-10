"""
tests/test_auth.py - Unit tests for the auth module
Covers login, logout, token validation, and session management.

Run with:  pytest tests/test_auth.py -v
"""

import time
import pytest
from unittest.mock import patch
from datetime import datetime, timedelta

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../src"))

from auth import (
    login,
    logout,
    validate_token,
    get_active_sessions,
    _hash_password,
    _generate_token,
    _is_token_expired,
    _sessions,
    TOKEN_EXPIRY_SECONDS,
)
from utils import generate_salt


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def clear_sessions():
    """Clear the in-memory session store before each test."""
    _sessions.clear()
    yield
    _sessions.clear()


@pytest.fixture
def mock_user_db():
    """Return a minimal fake user database with two users."""
    salt_grensi = generate_salt()
    salt_raj = generate_salt()

    return {
        "grensi": {
            "user_id": "usr_001",
            "salt": salt_grensi,
            "hashed_password": _hash_password("SecurePass@1", salt_grensi),
        },
        "raj": {
            "user_id": "usr_002",
            "salt": salt_raj,
            "hashed_password": _hash_password("RajPass@99", salt_raj),
        },
    }


# ── Login Tests ───────────────────────────────────────────────────────────────

class TestLogin:

    def test_successful_login_returns_token(self, mock_user_db):
        result = login("grensi", "SecurePass@1", mock_user_db)
        assert result["success"] is True
        assert result["token"] is not None
        assert result["message"] == "Login successful"

    def test_wrong_password_fails(self, mock_user_db):
        result = login("grensi", "WrongPassword!", mock_user_db)
        assert result["success"] is False
        assert result["token"] is None
        assert result["message"] == "Invalid credentials"

    def test_unknown_user_fails(self, mock_user_db):
        result = login("ghost_user", "anypassword", mock_user_db)
        assert result["success"] is False
        assert result["token"] is None

    def test_empty_password_fails(self, mock_user_db):
        result = login("grensi", "", mock_user_db)
        assert result["success"] is False

    def test_empty_username_fails(self, mock_user_db):
        result = login("", "SecurePass@1", mock_user_db)
        assert result["success"] is False

    def test_login_creates_session(self, mock_user_db):
        result = login("grensi", "SecurePass@1", mock_user_db)
        token = result["token"]
        assert token in _sessions
        assert _sessions[token]["username"] == "grensi"

    def test_two_different_users_get_different_tokens(self, mock_user_db):
        r1 = login("grensi", "SecurePass@1", mock_user_db)
        r2 = login("raj", "RajPass@99", mock_user_db)
        assert r1["token"] != r2["token"]

    def test_same_user_login_twice_gets_different_tokens(self, mock_user_db):
        r1 = login("grensi", "SecurePass@1", mock_user_db)
        r2 = login("grensi", "SecurePass@1", mock_user_db)
        assert r1["token"] != r2["token"]


# ── Logout Tests ──────────────────────────────────────────────────────────────

class TestLogout:

    def test_logout_removes_session(self, mock_user_db):
        result = login("grensi", "SecurePass@1", mock_user_db)
        token = result["token"]
        assert logout(token) is True
        assert token not in _sessions

    def test_logout_invalid_token_returns_false(self):
        assert logout("totally-fake-token") is False

    def test_double_logout_second_returns_false(self, mock_user_db):
        result = login("grensi", "SecurePass@1", mock_user_db)
        token = result["token"]
        logout(token)
        assert logout(token) is False

    def test_logout_does_not_affect_other_sessions(self, mock_user_db):
        r1 = login("grensi", "SecurePass@1", mock_user_db)
        r2 = login("raj", "RajPass@99", mock_user_db)
        logout(r1["token"])
        assert r2["token"] in _sessions


# ── Token Validation Tests ────────────────────────────────────────────────────

class TestValidateToken:

    def test_valid_token_returns_session(self, mock_user_db):
        result = login("grensi", "SecurePass@1", mock_user_db)
        session = validate_token(result["token"])
        assert session is not None
        assert session["username"] == "grensi"

    def test_fake_token_returns_none(self):
        assert validate_token("fake-token-xyz") is None

    def test_expired_token_returns_none(self, mock_user_db):
        result = login("grensi", "SecurePass@1", mock_user_db)
        token = result["token"]

        # Manually backdate the session creation time to simulate expiry
        _sessions[token]["created_at"] = datetime.utcnow() - timedelta(seconds=TOKEN_EXPIRY_SECONDS + 10)

        assert validate_token(token) is None

    def test_expired_token_is_removed_from_sessions(self, mock_user_db):
        result = login("grensi", "SecurePass@1", mock_user_db)
        token = result["token"]
        _sessions[token]["created_at"] = datetime.utcnow() - timedelta(seconds=TOKEN_EXPIRY_SECONDS + 10)
        validate_token(token)
        assert token not in _sessions

    def test_valid_token_refreshes_last_active(self, mock_user_db):
        result = login("grensi", "SecurePass@1", mock_user_db)
        token = result["token"]
        original_last_active = _sessions[token]["last_active"]
        time.sleep(0.05)
        validate_token(token)
        assert _sessions[token]["last_active"] > original_last_active

    def test_empty_token_returns_none(self):
        assert validate_token("") is None


# ── Active Sessions Tests ─────────────────────────────────────────────────────

class TestGetActiveSessions:

    def test_no_sessions_returns_empty_list(self):
        assert get_active_sessions() == []

    def test_active_session_appears_in_list(self, mock_user_db):
        login("grensi", "SecurePass@1", mock_user_db)
        sessions = get_active_sessions()
        assert len(sessions) == 1
        assert sessions[0]["username"] == "grensi"

    def test_multiple_sessions_all_returned(self, mock_user_db):
        login("grensi", "SecurePass@1", mock_user_db)
        login("raj", "RajPass@99", mock_user_db)
        sessions = get_active_sessions()
        usernames = [s["username"] for s in sessions]
        assert "grensi" in usernames
        assert "raj" in usernames

    def test_expired_sessions_excluded(self, mock_user_db):
        login("grensi", "SecurePass@1", mock_user_db)
        r2 = login("raj", "RajPass@99", mock_user_db)

        # Expire grensi's session
        for token, session in list(_sessions.items()):
            if session["username"] == "grensi":
                _sessions[token]["created_at"] = datetime.utcnow() - timedelta(seconds=TOKEN_EXPIRY_SECONDS + 10)

        sessions = get_active_sessions()
        usernames = [s["username"] for s in sessions]
        assert "grensi" not in usernames
        assert "raj" in usernames

    def test_session_data_has_expected_keys(self, mock_user_db):
        login("grensi", "SecurePass@1", mock_user_db)
        session = get_active_sessions()[0]
        assert "username" in session
        assert "user_id" in session
        assert "created_at" in session
        assert "last_active" in session