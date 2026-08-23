# Walkthrough: Secure RBAC System with USERA, USERB, USERC Personas

We have built a production-grade, secure Role-Based Authentication and Authorization (RBAC) system in FastAPI with asynchronous SQLAlchemy (asyncpg/PostgreSQL), JWT authentication, account lockout rate limiting, and clean architectural separation.

## Folder & File Structure

```
server/
├── .env                       # Environment configuration
├── .env.example               # Example template
├── requirements.txt           # Python dependencies
├── config.py                  # Settings proxy
├── main.py                    # FastAPI entrypoint with lifespan startup & DB seeder
├── tests/
│   ├── __init__.py
│   └── test_rbac.py           # Comprehensive automated pytest suite
└── app/
    ├── __init__.py
    ├── config.py              # Pydantic Settings (.env loader & validators)
    ├── api/
    │   ├── __init__.py
    │   └── deps.py            # Reusable Auth & RBAC Dependencies (get_current_user, require_roles, require_min_role)
    ├── routes/
    │   ├── __init__.py        # Aggregator API router
    │   ├── auth_routes.py     # /api/auth (register, login, refresh, me)
    │   ├── user_routes.py     # /api/users (profile, password updates)
    │   └── admin_routes.py    # /api/admin (user listing, unlock, role management)
    ├── db/
    │   ├── __init__.py
    │   ├── base.py            # SQLAlchemy Declarative Base & TimestampMixin
    │   └── session.py         # Async engine & session generator (get_db)
    ├── models/
    │   ├── __init__.py
    │   ├── enums.py           # UserRole (USERA, USERB, USERC) with hierarchy methods
    │   └── user.py            # User model with lockout state & security tracking
    ├── schemas/
    │   ├── __init__.py
    │   ├── auth.py            # RegisterRequest, LoginRequest, RefreshTokenRequest
    │   ├── token.py           # TokenPayload, TokenResponse
    │   └── user.py            # UserResponse, UserUpdateMe, UserRoleUpdate, PasswordChangeRequest
    ├── services/
    │   ├── __init__.py
    │   ├── auth_service.py    # Login attempt tracking, lockout calculations, token generation
    │   └── user_service.py    # User CRUD, role elevation checks, super admin seeder
    ├── middleware/
    │   ├── __init__.py
    │   └── error_handler.py   # Global exception handlers
    └── utils/
        ├── __init__.py
        └── security.py        # Bcrypt password hashing & PyJWT token utilities
```

---

## Key Features & Security Protections

### 1. Role Personas (`USERA`, `USERB`, `USERC`)
Defined in [`app/models/enums.py`](file:///d:/code/AIfriday/server/app/models/enums.py) with integer weights for hierarchy checks:
- **`USERA`** (Base Persona / User):
  - Created by default upon registration.
  - Can view and update own profile ([`/api/users/me`](file:///d:/code/AIfriday/server/app/routes/user_routes.py)), change password.
- **`USERB`** (Elevated Persona / Admin):
  - Can list all users with pagination & search ([`/api/admin/users`](file:///d:/code/AIfriday/server/app/routes/admin_routes.py)).
  - Can view user details and unlock accounts locked due to failed attempts ([`/api/admin/users/{id}/unlock`](file:///d:/code/AIfriday/server/app/routes/admin_routes.py)).
- **`USERC`** (Super Admin Persona):
  - Complete control: Can assign/elevate roles (`USERA`, `USERB`, `USERC`), delete accounts, and manage system security settings.
  - Seeded automatically on startup if configured in `.env`.

### 2. Login Rate Limiting & Account Lockout
- Managed via `MAX_LOGIN_ATTEMPTS=5` and `LOCKOUT_MINUTES=15`.
- Failed login attempts increment `failed_login_attempts`.
- On the 5th failed attempt, `locked_until` is set to `now + 15 minutes`.
- Any login attempt during lockout returns `HTTP 403 Forbidden` with the remaining lockout duration.
- Successful login clears `failed_login_attempts` to 0 and clears `locked_until`.

### 3. Privilege Escalation Prevention
- Public registration (`/api/auth/register`) strictly sets `role = UserRole.USERA`.
- Only `USERC` can modify user roles via `/api/admin/users/{user_id}/role`.
- `USERB` cannot elevate themselves or other accounts to `USERC`.

### 4. Reusable Dependencies
In [`app/api/deps.py`](file:///d:/code/AIfriday/server/app/api/deps.py):
- `get_db`: Asynchronous DB session generator with auto-commit/rollback.
- `get_current_user`: Validates JWT token and fetches active user.
- `get_current_active_user`: Ensures account is active.
- `require_roles(*roles)`: Protects endpoints by specific role list (e.g. `Depends(require_roles(UserRole.USERB, UserRole.USERC))`).
- `require_min_role(min_role)`: Protects endpoints by minimum hierarchy level.

---

## Verification Results

We executed the test suite with `pytest`:

```bash
.\venv\Scripts\python.exe -m pytest tests/test_rbac.py -v
```

### Output:
```
============================= test session starts =============================
platform win32 -- Python 3.11.2, pytest-9.1.1, pluggy-1.6.0
collecting ... collected 5 items

tests/test_rbac.py::test_password_hashing PASSED                         [ 20%]
tests/test_rbac.py::test_jwt_tokens PASSED                              [ 40%]
tests/test_rbac.py::test_registration_and_login_flow PASSED             [ 60%]
tests/test_rbac.py::test_account_lockout_after_max_attempts PASSED      [ 80%]
tests/test_rbac.py::test_rbac_authorization PASSED                      [100%]

============================== 5 passed in 20.37s ==============================
```

All 5 comprehensive test suites passed covering password hashing, JWT claims, registration, lockout rate limiting, and RBAC endpoint gating.
