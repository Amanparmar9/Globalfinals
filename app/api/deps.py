from typing import Callable, List, Sequence
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db
from app.models.enums import UserRole
from app.models.user import User
from app.services.user_service import UserService
from app.utils.security import decode_token

# OAuth2 scheme for extracting Bearer token from Authorization header
oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl="/api/auth/login",
    description="JWT Bearer token authentication",
    auto_error=True,
)


async def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_db),
) -> User:
    """
    Dependency that decodes the JWT access token and fetches the corresponding active user from DB.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials.",
        headers={"WWW-Authenticate": "Bearer"},
    )

    payload = decode_token(token)
    if payload.get("type") != "access":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token type: Expected access token.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user_id: str = payload.get("sub")
    if not user_id:
        raise credentials_exception

    user = await UserService.get_by_id(db, user_id)
    if not user:
        raise credentials_exception

    return user


async def get_current_active_user(
    current_user: User = Depends(get_current_user),
) -> User:
    """
    Dependency that ensures the authenticated user account is active.
    """
    if not current_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Inactive user account. Access denied.",
        )
    return current_user


def require_roles(*allowed_roles: UserRole) -> Callable:
    """
    Role-Based Access Control (RBAC) Dependency Factory.
    Ensures that the authenticated user possesses one of the specified roles.

    Usage:
        @router.get("/admin-only", dependencies=[Depends(require_roles(UserRole.USERB, UserRole.USERC))])
    """
    async def role_checker(
        current_user: User = Depends(get_current_active_user),
    ) -> User:
        if current_user.role not in allowed_roles:
            role_names = ", ".join([r.value for r in allowed_roles])
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access forbidden: Requires one of the following roles: [{role_names}]. Current role: {current_user.role.value}",
            )
        return current_user

    return role_checker


def require_min_role(min_role: UserRole) -> Callable:
    """
    Hierarchy-Based Access Control Dependency Factory.
    Ensures that the authenticated user possesses at least the specified hierarchy level:
    USERA (Level 1) < USERB (Level 2) < USERC (Level 3).

    Usage:
        @router.get("/elevated", dependencies=[Depends(require_min_role(UserRole.USERB))])
    """
    async def hierarchy_checker(
        current_user: User = Depends(get_current_active_user),
    ) -> User:
        if not current_user.role.is_at_least(min_role):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access forbidden: Requires minimum role level '{min_role.value}'. Current role: '{current_user.role.value}'",
            )
        return current_user

    return hierarchy_checker
