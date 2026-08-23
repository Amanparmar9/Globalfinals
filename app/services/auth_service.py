import datetime
from typing import Optional, Tuple
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from fastapi import HTTPException, status

from app.config import settings
from app.models.user import User
from app.schemas.token import TokenResponse
from app.utils.security import (
    create_access_token,
    create_refresh_token,
    decode_token,
    verify_password,
)


class AuthService:
    @staticmethod
    async def get_user_by_identifier(
        db: AsyncSession,
        identifier: str
    ) -> Optional[User]:
        """Find a user by username or email (case-insensitive for email)."""
        clean_identifier = identifier.strip()
        query = select(User).where(
            or_(
                User.username == clean_identifier.lower(),
                User.email == clean_identifier.lower(),
            )
        )
        result = await db.execute(query)
        return result.scalar_one_or_none()

    @staticmethod
    async def authenticate_user(
        db: AsyncSession,
        username_or_email: str,
        password: str,
    ) -> Tuple[User, TokenResponse]:
        """
        Authenticate a user with rate limiting and account lockout enforcement.
        """
        now = datetime.datetime.now(datetime.timezone.utc)
        user = await AuthService.get_user_by_identifier(db, username_or_email)

        # Generic error message to prevent account enumeration
        invalid_credentials_exception = HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials.",
            headers={"WWW-Authenticate": "Bearer"},
        )

        if not user:
            # Constant-time dummy check could be added, but for now reject
            raise invalid_credentials_exception

        if not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Account is deactivated. Please contact an administrator.",
            )

        # Check if account is currently locked
        if user.is_locked:
            remaining_seconds = user.remaining_lockout_seconds
            remaining_minutes = max(1, (remaining_seconds + 59) // 60)
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=(
                    f"Account is temporarily locked due to excessive failed login attempts. "
                    f"Please try again in {remaining_minutes} minute(s)."
                ),
            )

        # If lockout period expired, automatically reset the counter
        if user.locked_until and user.locked_until <= now:
            user.failed_login_attempts = 0
            user.locked_until = None

        # Verify password
        if not verify_password(password, user.hashed_password):
            user.failed_login_attempts += 1

            # Lock the account if max attempts exceeded
            if user.failed_login_attempts >= settings.MAX_LOGIN_ATTEMPTS:
                user.locked_until = now + datetime.timedelta(minutes=settings.LOCKOUT_MINUTES)
                await db.commit()
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=(
                        f"Account locked! Maximum failed login attempts reached ({settings.MAX_LOGIN_ATTEMPTS}). "
                        f"Account is locked for {settings.LOCKOUT_MINUTES} minutes."
                    ),
                )

            await db.commit()
            attempts_left = settings.MAX_LOGIN_ATTEMPTS - user.failed_login_attempts
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Invalid credentials. {attempts_left} attempt(s) remaining before lockout.",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Successful login: reset failed attempts & lockout, update last_login_at
        user.failed_login_attempts = 0
        user.locked_until = None
        user.last_login_at = now
        await db.commit()
        await db.refresh(user)

        # Build JWT tokens
        token_claims = {
            "username": user.username,
            "email": user.email,
            "role": user.role.value,
        }
        access_token = create_access_token(subject=user.id, claims=token_claims)
        refresh_token = create_refresh_token(subject=user.id, claims=token_claims)

        token_response = TokenResponse(
            access_token=access_token,
            refresh_token=refresh_token,
            token_type="bearer",
            expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            role=user.role,
            user_id=user.id,
            username=user.username,
        )
        return user, token_response

    @staticmethod
    async def refresh_tokens(
        db: AsyncSession,
        refresh_token: str,
    ) -> TokenResponse:
        """
        Validate a refresh token and issue a fresh access token.
        """
        payload = decode_token(refresh_token)
        if payload.get("type") != "refresh":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token type for refresh endpoint.",
            )

        user_id = payload.get("sub")
        query = select(User).where(User.id == user_id)
        result = await db.execute(query)
        user = result.scalar_one_or_none()

        if not user or not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User account not found or inactive.",
            )

        token_claims = {
            "username": user.username,
            "email": user.email,
            "role": user.role.value,
        }
        new_access_token = create_access_token(subject=user.id, claims=token_claims)
        new_refresh_token = create_refresh_token(subject=user.id, claims=token_claims)

        return TokenResponse(
            access_token=new_access_token,
            refresh_token=new_refresh_token,
            token_type="bearer",
            expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            role=user.role,
            user_id=user.id,
            username=user.username,
        )
