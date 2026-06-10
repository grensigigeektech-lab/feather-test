"""
utils.py - Shared utility/helper functions for iGeek platform
General-purpose helpers used across auth, api, and other modules.

Recent refactor: cleaned up helper functions — removed duplication,
added type hints, and improved error handling throughout.
"""

import re
import json
import logging
import hashlib
import secrets
from datetime import datetime, timezone
from typing import Any, Optional, Union

logger = logging.getLogger(__name__)


# ── String Utilities ──────────────────────────────────────────────────────────

def sanitize_string(value: str, max_length: int = 255) -> str:
    """
    Strip whitespace and truncate a string to max_length.
    Returns empty string if input is not a valid string.
    """
    if not isinstance(value, str):
        return ""
    return value.strip()[:max_length]


def slugify(text: str) -> str:
    """
    Convert a string to a URL-safe slug.
    e.g. "Hello World!" → "hello-world"
    """
    text = text.lower().strip()
    text = re.sub(r"[^\w\s-]", "", text)
    text = re.sub(r"[\s_-]+", "-", text)
    text = re.sub(r"^-+|-+$", "", text)
    return text


def mask_sensitive(value: str, visible_chars: int = 4) -> str:
    """
    Mask a sensitive string, leaving only the last N chars visible.
    e.g. mask_sensitive("mysecrettoken", 4) → "*********oken"
    """
    if len(value) <= visible_chars:
        return "*" * len(value)
    return "*" * (len(value) - visible_chars) + value[-visible_chars:]


# ── Security Utilities ────────────────────────────────────────────────────────

def generate_salt(length: int = 32) -> str:
    """Generate a cryptographically secure random salt string."""
    return secrets.token_hex(length)


def generate_otp(digits: int = 6) -> str:
    """Generate a numeric OTP of the given length."""
    return "".join([str(secrets.randbelow(10)) for _ in range(digits)])


def hash_value(value: str, salt: str = "") -> str:
    """Return a SHA-256 hash of value + salt."""
    combined = (value + salt).encode("utf-8")
    return hashlib.sha256(combined).hexdigest()


# ── Date / Time Utilities ─────────────────────────────────────────────────────

def utc_now() -> datetime:
    """Return the current UTC datetime (timezone-aware)."""
    return datetime.now(timezone.utc)


def format_datetime(dt: datetime, fmt: str = "%Y-%m-%d %H:%M:%S") -> str:
    """Format a datetime object to a readable string."""
    if not isinstance(dt, datetime):
        return ""
    return dt.strftime(fmt)


def days_between(start: datetime, end: datetime) -> int:
    """Return the number of whole days between two datetime objects."""
    delta = end - start
    return abs(delta.days)


def is_within_window(dt: datetime, hours: int = 24) -> bool:
    """Return True if dt is within the last N hours from now."""
    now = utc_now()
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    diff = now - dt
    return diff.total_seconds() <= hours * 3600


# ── Data Utilities ────────────────────────────────────────────────────────────

def safe_json_parse(raw: str, fallback: Any = None) -> Any:
    """
    Safely parse a JSON string, returning fallback on failure.
    """
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, TypeError) as exc:
        logger.warning("JSON parse failed: %s", exc)
        return fallback


def flatten_dict(d: dict, parent_key: str = "", sep: str = ".") -> dict:
    """
    Flatten a nested dictionary.
    e.g. {"a": {"b": 1}} → {"a.b": 1}
    """
    items = {}
    for k, v in d.items():
        new_key = f"{parent_key}{sep}{k}" if parent_key else k
        if isinstance(v, dict):
            items.update(flatten_dict(v, new_key, sep=sep))
        else:
            items[new_key] = v
    return items


def paginate(items: list, page: int = 1, limit: int = 20) -> dict:
    """
    Paginate a list and return a structured result.

    Returns:
        {
            items: [...],
            page: int,
            limit: int,
            total: int,
            total_pages: int,
            has_next: bool,
            has_prev: bool
        }
    """
    total = len(items)
    total_pages = max(1, -(-total // limit))  # ceiling division
    page = max(1, min(page, total_pages))
    start = (page - 1) * limit
    end = start + limit

    return {
        "items": items[start:end],
        "page": page,
        "limit": limit,
        "total": total,
        "total_pages": total_pages,
        "has_next": page < total_pages,
        "has_prev": page > 1,
    }


# ── Logging Utilities ─────────────────────────────────────────────────────────

def setup_logger(name: str, level: int = logging.INFO) -> logging.Logger:
    """
    Create and configure a named logger with a standard formatter.
    """
    log = logging.getLogger(name)
    if not log.handlers:
        handler = logging.StreamHandler()
        formatter = logging.Formatter(
            "[%(asctime)s] %(levelname)s %(name)s — %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        handler.setFormatter(formatter)
        log.addHandler(handler)
    log.setLevel(level)
    return log


# ── Validation Utilities ──────────────────────────────────────────────────────

def is_non_empty_string(value: Any) -> bool:
    """Return True if value is a non-empty string after stripping."""
    return isinstance(value, str) and bool(value.strip())


def coerce_bool(value: Any) -> Optional[bool]:
    """
    Safely coerce common truthy/falsy values to bool.
    Returns None if value cannot be interpreted.
    """
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        if value.lower() in ("true", "1", "yes"):
            return True
        if value.lower() in ("false", "0", "no"):
            return False
    if isinstance(value, int):
        return bool(value)
    return None


def required_fields(data: dict, fields: list[str]) -> list[str]:
    """
    Check that all required fields are present and non-empty in data.
    Returns a list of missing field names.
    """
    missing = []
    for field in fields:
        val = data.get(field)
        if val is None or (isinstance(val, str) and not val.strip()):
            missing.append(field)
    return missing