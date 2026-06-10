import re
import logging
from typing import Any, Optional
from datetime import datetime

from auth import validate_token

logger = logging.getLogger(__name__)

# ── Response Helpers ──────────────────────────────────────────────────────────

def success_response(data: Any, message: str = "OK", status: int = 200) -> dict:
    """Standard success response envelope."""
    return {
        "status": status,
        "success": True,
        "message": message,
        "data": data,
        "timestamp": datetime.utcnow().isoformat(),
    }


def error_response(message: str, status: int = 400, errors: list = None) -> dict:
    """Standard error response envelope."""
    return {
        "status": status,
        "success": False,
        "message": message,
        "errors": errors or [],
        "timestamp": datetime.utcnow().isoformat(),
    }


# ── Input Validators ──────────────────────────────────────────────────────────

def validate_email(email: str) -> tuple[bool, str]:
    """
    Validate email format.
    Returns (is_valid: bool, error_message: str)
    """
    if not email or not isinstance(email, str):
        return False, "Email is required and must be a string"
    email = email.strip()
    pattern = r"^[\w\.-]+@[\w\.-]+\.\w{2,}$"
    if not re.match(pattern, email):
        return False, f"'{email}' is not a valid email address"
    if len(email) > 254:
        return False, "Email address is too long"
    return True, ""


def validate_username(username: str) -> tuple[bool, str]:
    """
    Validate username format.
    Must be 3-30 chars, alphanumeric + underscores only.
    """
    if not username or not isinstance(username, str):
        return False, "Username is required"
    username = username.strip()
    if len(username) < 3:
        return False, "Username must be at least 3 characters"
    if len(username) > 30:
        return False, "Username must be 30 characters or fewer"
    if not re.match(r"^[a-zA-Z0-9_]+$", username):
        return False, "Username can only contain letters, numbers, and underscores"
    return True, ""


def validate_password(password: str) -> tuple[bool, str]:
    """
    Validate password strength.
    Min 8 chars, must include uppercase, lowercase, digit, special char.
    """
    if not password or not isinstance(password, str):
        return False, "Password is required"
    errors = []
    if len(password) < 8:
        errors.append("at least 8 characters")
    if not re.search(r"[A-Z]", password):
        errors.append("an uppercase letter")
    if not re.search(r"[a-z]", password):
        errors.append("a lowercase letter")
    if not re.search(r"\d", password):
        errors.append("a number")
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        errors.append("a special character")
    if errors:
        return False, "Password must contain: " + ", ".join(errors)
    return True, ""


def validate_pagination(page: Any, limit: Any) -> tuple[bool, str, int, int]:
    """
    Validate and sanitize pagination parameters.
    Returns (is_valid, error_msg, safe_page, safe_limit)
    """
    try:
        page = int(page) if page is not None else 1
        limit = int(limit) if limit is not None else 20
    except (ValueError, TypeError):
        return False, "Page and limit must be integers", 1, 20

    if page < 1:
        return False, "Page must be 1 or greater", 1, 20
    if limit < 1 or limit > 100:
        return False, "Limit must be between 1 and 100", 1, 20

    return True, "", page, limit


# ── Auth Middleware ───────────────────────────────────────────────────────────

def require_auth(token: Optional[str]) -> tuple[bool, Optional[dict], dict]:
    """
    Check bearer token and return session if valid.
    Returns (is_authenticated, session_data, error_response_if_any)
    """
    if not token:
        return False, None, error_response("Authentication token is required", status=401)

    session = validate_token(token)
    if not session:
        return False, None, error_response("Invalid or expired token", status=401)

    return True, session, {}


# ── API Endpoint Handlers ─────────────────────────────────────────────────────

def handle_register(body: dict, user_db: dict) -> dict:
    """
    POST /api/register
    Expected body: { username, email, password }
    """
    validation_errors = []

    username = body.get("username", "")
    email = body.get("email", "")
    password = body.get("password", "")

    valid, msg = validate_username(username)
    if not valid:
        validation_errors.append({"field": "username", "message": msg})

    valid, msg = validate_email(email)
    if not valid:
        validation_errors.append({"field": "email", "message": msg})

    valid, msg = validate_password(password)
    if not valid:
        validation_errors.append({"field": "password", "message": msg})

    if validation_errors:
        logger.warning("Registration validation failed: %s", validation_errors)
        return error_response("Validation failed", status=422, errors=validation_errors)

    if username in user_db:
        return error_response("Username already taken", status=409)

    logger.info("New user registered: %s", username)
    return success_response(
        data={"username": username, "email": email},
        message="User registered successfully",
        status=201
    )


def handle_get_users(token: str, query_params: dict, user_db: dict) -> dict:
    """
    GET /api/users
    Requires valid auth token. Supports ?page=&limit= pagination.
    """
    is_auth, session, err = require_auth(token)
    if not is_auth:
        return err

    page_raw = query_params.get("page", 1)
    limit_raw = query_params.get("limit", 20)

    valid, msg, page, limit = validate_pagination(page_raw, limit_raw)
    if not valid:
        return error_response(msg, status=422)

    all_users = list(user_db.keys())
    start = (page - 1) * limit
    end = start + limit
    paginated = all_users[start:end]

    return success_response(data={
        "users": paginated,
        "page": page,
        "limit": limit,
        "total": len(all_users),
    })


def handle_update_user(token: str, username: str, body: dict, user_db: dict) -> dict:
    """
    PUT /api/users/<username>
    Requires valid auth token. Only the user themselves can update their profile.
    """
    is_auth, session, err = require_auth(token)
    if not is_auth:
        return err

    if session["username"] != username:
        return error_response("You can only update your own profile", status=403)

    if username not in user_db:
        return error_response("User not found", status=404)

    validation_errors = []

    new_email = body.get("email")
    if new_email is not None:
        valid, msg = validate_email(new_email)
        if not valid:
            validation_errors.append({"field": "email", "message": msg})

    new_password = body.get("password")
    if new_password is not None:
        valid, msg = validate_password(new_password)
        if not valid:
            validation_errors.append({"field": "password", "message": msg})

    if validation_errors:
        return error_response("Validation failed", status=422, errors=validation_errors)

    logger.info("User %s profile updated", username)
    return success_response(data={"username": username}, message="Profile updated successfully")