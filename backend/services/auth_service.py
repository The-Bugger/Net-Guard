"""
auth_service.py — Authentication and user management for Net-Guard Enterprise IDPS.

Provides JWT-based session auth, TOTP MFA, and password-policy enforcement.

Requirements: 14.1, 14.4, 14.6
"""

from __future__ import annotations

import logging
import secrets
import string
import threading
from datetime import datetime, timezone, timedelta

import jwt
import pyotp
from werkzeug.security import check_password_hash, generate_password_hash

from database.schema import UserAccount

logger = logging.getLogger("netguard.auth_service")

_ROLES = {"admin", "analyst", "hunter", "viewer"}
_JWT_ALGORITHM = "HS256"
_ACCESS_EXPIRY_HOURS = 8
_REFRESH_EXPIRY_DAYS = 30

# Known insecure default from earlier releases — never sign with this.
# If found in the settings DB it is rotated automatically on next use.
_LEGACY_DEFAULT_SECRET = "netguard-change-in-production"


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class AuthService:
    """JWT + TOTP authentication and user management."""

    def __init__(self, settings_repo, audit_service) -> None:
        self._settings_repo = settings_repo
        self._audit = audit_service
        self._secret_cache: str | None = None
        self._secret_lock = threading.Lock()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _secret(self) -> str:
        """
        Return the JWT signing secret.

        The secret lives in the settings DB (key ``jwt_secret``). When it is
        missing — or still set to the legacy known default — a cryptographically
        random secret is generated, persisted, and reused from an in-process
        cache afterwards. A security appliance must never sign tokens with a
        publicly-known constant.

        If the DB write fails, a per-process ephemeral secret is used instead
        (tokens become invalid on restart — a safe failure mode, never an
        insecure one).
        """
        if self._secret_cache is not None:
            return self._secret_cache

        with self._secret_lock:
            if self._secret_cache is not None:
                return self._secret_cache

            stored = None
            if self._settings_repo is not None:
                try:
                    stored = self._settings_repo.get("jwt_secret")
                except Exception:
                    stored = None

            if stored and stored != _LEGACY_DEFAULT_SECRET:
                self._secret_cache = stored
                return stored

            new_secret = secrets.token_urlsafe(48)
            persisted = False
            if self._settings_repo is not None:
                try:
                    persisted = bool(self._settings_repo.set("jwt_secret", new_secret))
                except Exception:
                    persisted = False

            if persisted:
                logger.warning(
                    "JWT signing secret was missing or used the known legacy default — "
                    "a new random secret was generated and persisted. All previously "
                    "issued tokens are now invalid; users must log in again."
                )
            else:
                logger.error(
                    "Could not persist a JWT signing secret — using a per-process "
                    "ephemeral secret. Tokens will not survive a restart."
                )
            self._secret_cache = new_secret
            return new_secret

    def _session_factory(self):
        # Pulled lazily from the DI registry. NEVER import backend.main
        # here: when main.py runs as __main__ (python backend/main.py),
        # importing backend.main creates a second module instance with its
        # own session_factory/engine — two DB pools, split state.
        from backend.api import dependencies
        factory = dependencies.get("session_factory")
        if factory is None:
            raise RuntimeError("session_factory not registered in DI registry")
        return factory

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def login(self, username: str, password: str, totp_code: str | None = None) -> dict:
        """
        Authenticate a user and return JWT tokens.

        Raises:
            ValueError: with code LOGIN_FAILED, MFA_REQUIRED, or MFA_INVALID.
        """
        with self._session_factory()() as session:
            user = session.query(UserAccount).filter_by(username=username, active=1).first()
            if not user or not check_password_hash(user.password_hash, password):
                self._audit.log("anonymous", "LOGIN_FAILED", "/api/v1/auth/login", {"username": username})
                raise ValueError("LOGIN_FAILED")

            if user.mfa_enabled:
                if not totp_code:
                    raise ValueError("MFA_REQUIRED")
                totp = pyotp.TOTP(user.mfa_secret)
                if not totp.verify(totp_code, valid_window=1):
                    self._audit.log(username, "MFA_INVALID", "/api/v1/auth/login", {})
                    raise ValueError("MFA_INVALID")

            user.last_login = _utc_now()
            # Read role inside the session before it expires (avoids DetachedInstanceError)
            role = user.role
            session.commit()

        self._audit.log(username, "LOGIN", "/api/v1/auth/login", {})
        return {
            "access_token": self._make_access_token(username, role),
            "refresh_token": self._make_refresh_token(username),
            "role": role,
        }

    def refresh(self, refresh_token: str) -> dict:
        """Return a new access token given a valid refresh token."""
        payload = self.validate_token(refresh_token)
        if payload.get("type") != "refresh":
            raise ValueError("INVALID_TOKEN")
        username = payload["sub"]
        with self._session_factory()() as session:
            user = session.query(UserAccount).filter_by(username=username, active=1).first()
            if not user:
                raise ValueError("USER_NOT_FOUND")
            role = user.role  # read inside session
        return {"access_token": self._make_access_token(username, role)}

    def create_user(self, username: str, password: str, role: str) -> dict:
        """
        Create a new user account enforcing password policy.

        Raises:
            ValueError: with human-readable unmet criteria list.
        """
        if role not in _ROLES:
            raise ValueError(f"Invalid role. Must be one of: {', '.join(sorted(_ROLES))}")
        issues = _password_policy_issues(password)
        if issues:
            raise ValueError("Password policy not met: " + "; ".join(issues))

        now = _utc_now()
        with self._session_factory()() as session:
            if session.query(UserAccount).filter_by(username=username).first():
                raise ValueError("USERNAME_TAKEN")
            user = UserAccount(
                username=username,
                password_hash=generate_password_hash(password),
                role=role,
                created_at=now,
                active=1,
            )
            session.add(user)
            session.commit()
            uid = user.id

        self._audit.log("system", "USER_CREATED", "/api/v1/auth/users", {"username": username, "role": role})
        return {"id": uid, "username": username, "role": role, "created_at": now}

    def validate_token(self, token: str) -> dict:
        """
        Decode and validate a JWT.

        Raises:
            ValueError: on invalid, expired, or malformed token.
        """
        try:
            return jwt.decode(token, self._secret(), algorithms=[_JWT_ALGORITHM])
        except jwt.ExpiredSignatureError:
            raise ValueError("TOKEN_EXPIRED")
        except jwt.InvalidTokenError as exc:
            raise ValueError(f"INVALID_TOKEN: {exc}")

    # ------------------------------------------------------------------
    # Token builders
    # ------------------------------------------------------------------

    def _make_access_token(self, username: str, role: str) -> str:
        exp = datetime.now(timezone.utc) + timedelta(hours=_ACCESS_EXPIRY_HOURS)
        return jwt.encode(
            {"sub": username, "role": role, "type": "access", "exp": exp},
            self._secret(), algorithm=_JWT_ALGORITHM,
        )

    def _make_refresh_token(self, username: str) -> str:
        exp = datetime.now(timezone.utc) + timedelta(days=_REFRESH_EXPIRY_DAYS)
        return jwt.encode(
            {"sub": username, "type": "refresh", "exp": exp},
            self._secret(), algorithm=_JWT_ALGORITHM,
        )


# ---------------------------------------------------------------------------
# Password policy (pure function — used by property test)
# ---------------------------------------------------------------------------

def _password_policy_issues(password: str) -> list[str]:
    """Return list of unmet password policy criteria (empty = OK)."""
    issues = []
    if len(password) < 12:
        issues.append("at least 12 characters")
    if not any(c.isupper() for c in password):
        issues.append("at least one uppercase letter")
    if not any(c.isdigit() for c in password):
        issues.append("at least one digit")
    if not any(c in string.punctuation for c in password):
        issues.append("at least one special character")
    return issues


def password_policy_valid(password: str) -> bool:
    """Return True iff password meets all policy criteria."""
    return len(_password_policy_issues(password)) == 0
