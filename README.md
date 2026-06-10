# iGeek Test Project

Backend auth and API service for the iGeek platform.

## Structure

```
src/
  auth.py       # Login, logout, token management
  api.py        # Input validation, request handlers
  utils.py      # Shared helpers
tests/
  test_auth.py  # Auth unit tests
.env.example    # Env variable template
```

## Setup

```bash
git clone https://github.com/your-org/igeek-test-project.git
cd igeek-test-project
pip install -r requirements.txt
cp .env.example .env
```

## Run Tests

```bash
pytest tests/ -v
```

## Current Sprint

| ID | Title | Status |
|----|-------|--------|
| DEV-01 | Fix login timeout bug | ✅ Done |
| DEV-02 | Add input validation to API | ✅ Done |
| DEV-03 | Refactor database connection pool | 🔄 In Progress |
| DEV-04 | Write unit tests for auth module | 🔄 In Progress |
| DEV-05 | Update API documentation | 📋 Todo |
| DEV-06 | Fix mobile UI alignment issue | 🚫 Blocked |

## Open PRs

**PR #1 — Improve auth flow and add input validation**
Branch: `feature/auth-improvements` → `main` · Author: Grensi · Awaiting review

## Tech Stack

Python 3.11 · pytest · HMAC-SHA256 sessions · PostgreSQL (planned)# igeek-test-project
# igeek-test-project
# feather-test
# feather-test
