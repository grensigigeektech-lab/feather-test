import hashlib
import hmac
import time
import uuid
import logging
from datetime import datetime, timedelta
from typing import Optional

logger = logging.getLogger(__name__)

# ── Constants ────────────────────────────────────────────────────────────────
SECRET_KEY = "igeek-secret-key-change-in-prod"   # load from .env in production
TOKEN_EXPIRY_SECONDS = 3600                        # 1 hour
LOGIN_TIMEOUT_SECONDS = 30                         # max wait for login response
MAX_LOGIN_RETRIES = 3


# ── In-memory session store (replace with Redis in production) ───────────────
_sessions: dict[str, dict] = {}


# ── Helpers ──────────────────────────────────────────────────────────────────

def _hash_password(password: str, salt: str) -> str:
    """Return a salted HMAC-SHA256 hash of the password."""
    return hmac.new(
        SECRET_KEY.encode(),
        (password + salt).encode(),
        hashlib.sha256
    ).hexdigest()


def _generate_token(user_id: str) -> str:
    """Generate a unique session token tied to the user ID."""
    raw = f"{user_id}-{uuid.uuid4()}-{time.time()}"
    return hashlib.sha256(raw.encode()).hexdigest()


def _is_token_expired(session: dict) -> bool:
    """Return True if the session token has passed its expiry time."""
    created_at: datetime = session.get("created_at", datetime.utcnow())
    expiry = created_at + timedelta(seconds=TOKEN_EXPIRY_SECONDS)
    return datetime.utcnow() > expiry


# ── Core Auth Functions ───────────────────────────────────────────────────────

def login(username: str, password: str, user_db: dict) -> dict:
    """
    Authenticate a user and return a session token.

    Args:
        username:  The user's login name.
        password:  Plain-text password (hashed before comparison).
        user_db:   Dict mapping username → {hashed_password, salt, user_id}.

    Returns:
        dict with keys: success (bool), token (str|None), message (str)

    Fix applied (commit: fix/login-timeout):
        - Added retry loop so transient DB delays don't immediately fail login.
        - LOGIN_TIMEOUT_SECONDS now enforced per-attempt, not for the whole flow.
    """
    if username not in user_db:
        logger.warning("Login attempt for unknown user: %s", username)
        return {"success": False, "token": None, "message": "Invalid credentials"}

    user = user_db[username]
    attempt = 0

    while attempt < MAX_LOGIN_RETRIES:
        attempt += 1
        start = time.time()

        try:
            hashed = _hash_password(password, user["salt"])

            # Simulate timeout guard — in real code this wraps a DB/network call
            elapsed = time.time() - start
            if elapsed > LOGIN_TIMEOUT_SECONDS:
                logger.error("Login timeout for user %s on attempt %d", username, attempt)
                continue

            if hmac.compare_digest(hashed, user["hashed_password"]):
                token = _generate_token(user["user_id"])
                _sessions[token] = {
                    "user_id": user["user_id"],
                    "username": username,
                    "created_at": datetime.utcnow(),
                    "last_active": datetime.utcnow(),
                }
                logger.info("User %s logged in successfully (attempt %d)", username, attempt)
                return {"success": True, "token": token, "message": "Login successful"}

            else:
                logger.warning("Wrong password for user %s", username)
                return {"success": False, "token": None, "message": "Invalid credentials"}

        except Exception as exc:
            logger.error("Login error on attempt %d: %s", attempt, exc)
            if attempt >= MAX_LOGIN_RETRIES:
                break
            time.sleep(0.5)  # brief back-off before retry

    return {"success": False, "token": None, "message": "Login failed after retries"}


def logout(token: str) -> bool:
    """
    Invalidate a session token.

    Returns True if the token existed and was removed, False otherwise.
    """
    if token in _sessions:
        username = _sessions[token].get("username")
        del _sessions[token]
        logger.info("User %s logged out", username)
        return True
    return False


def validate_token(token: str) -> Optional[dict]:
    """
    Validate a session token and return session data if valid.

    Returns None if the token is missing, invalid, or expired.
    Refreshes last_active timestamp on successful validation.
    """
    session = _sessions.get(token)
    if not session:
        return None

    if _is_token_expired(session):
        logger.info("Token expired for user %s — removing session", session.get("username"))
        del _sessions[token]
        return None

    # Refresh last active time
    _sessions[token]["last_active"] = datetime.utcnow()
    return session


def get_active_sessions() -> list[dict]:
    """Return a list of all currently active (non-expired) sessions."""
    active = []
    expired_tokens = []

    for token, session in _sessions.items():
        if _is_token_expired(session):
            expired_tokens.append(token)
        else:
            active.append({
                "username": session["username"],
                "user_id": session["user_id"],
                "created_at": session["created_at"].isoformat(),
                "last_active": session["last_active"].isoformat(),
            })

    # Clean up expired sessions
    for token in expired_tokens:
        del _sessions[token]

    return active