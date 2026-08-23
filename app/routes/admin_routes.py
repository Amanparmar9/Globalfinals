from typing import List, Optional
from fastapi import APIRouter, Depends, Query, status
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db, require_roles
from app.models.enums import UserRole
from app.models.user import User
from app.schemas.auth import MessageResponse
from app.schemas.user import AdminUserUpdate, UserResponse, UserRoleUpdate
from app.services.user_service import UserService

router = APIRouter(prefix="/admin", tags=["Administration & RBAC"])


class PaginatedUsersResponse(BaseModel):
    items: List[UserResponse]
    total: int
    skip: int
    limit: int


@router.get(
    "/users",
    response_model=PaginatedUsersResponse,
    status_code=status.HTTP_200_OK,
    summary="List all users (USERB or USERC)",
    description="List all registered accounts with pagination, optional role filtering, and search.",
)
async def list_users(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    role: Optional[UserRole] = Query(None, description="Filter by role: USERA, USERB, USERC"),
    search: Optional[str] = Query(None, description="Search by username, email, or full name"),
    current_admin: User = Depends(require_roles(UserRole.USERB, UserRole.USERC)),
    db: AsyncSession = Depends(get_db),
) -> PaginatedUsersResponse:
    """List users for administrators."""
    users, total = await UserService.list_users(
        db=db,
        skip=skip,
        limit=limit,
        role=role,
        search=search,
    )
    return PaginatedUsersResponse(
        items=[UserResponse.model_validate(u) for u in users],
        total=total,
        skip=skip,
        limit=limit,
    )


@router.get(
    "/users/{user_id}",
    response_model=UserResponse,
    status_code=status.HTTP_200_OK,
    summary="Get user details by ID (USERB or USERC)",
)
async def get_user_by_id(
    user_id: str,
    current_admin: User = Depends(require_roles(UserRole.USERB, UserRole.USERC)),
    db: AsyncSession = Depends(get_db),
) -> User:
    """Retrieve detailed user information including lockout state."""
    user = await UserService.get_by_id(db, user_id)
    if not user:
        from fastapi import HTTPException
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found.",
        )
    return user


@router.patch(
    "/users/{user_id}",
    response_model=UserResponse,
    status_code=status.HTTP_200_OK,
    summary="Update user status (USERB or USERC)",
)
async def update_user(
    user_id: str,
    data: AdminUserUpdate,
    current_admin: User = Depends(require_roles(UserRole.USERB, UserRole.USERC)),
    db: AsyncSession = Depends(get_db),
) -> User:
    """Update user account active/verified status."""
    return await UserService.admin_update_user(
        db=db,
        target_user_id=user_id,
        data=data,
        performing_admin=current_admin,
    )


@router.post(
    "/users/{user_id}/unlock",
    response_model=UserResponse,
    status_code=status.HTTP_200_OK,
    summary="Unlock locked account (USERB or USERC)",
    description="Manually unlock a locked user account and reset failed login attempts.",
)
async def unlock_user(
    user_id: str,
    current_admin: User = Depends(require_roles(UserRole.USERB, UserRole.USERC)),
    db: AsyncSession = Depends(get_db),
) -> User:
    """Unlock account for a user."""
    return await UserService.unlock_user(
        db=db,
        target_user_id=user_id,
        performing_admin=current_admin,
    )


@router.patch(
    "/users/{user_id}/role",
    response_model=UserResponse,
    status_code=status.HTTP_200_OK,
    summary="Update user role (Strictly USERC / Super Admin only)",
    description="Assign USERA, USERB, or USERC role. Only USERC can assign roles.",
)
async def change_user_role(
    user_id: str,
    data: UserRoleUpdate,
    current_super_admin: User = Depends(require_roles(UserRole.USERC)),
    db: AsyncSession = Depends(get_db),
) -> User:
    """Elevate or modify user role. Protected for USERC persona only."""
    return await UserService.update_user_role(
        db=db,
        target_user_id=user_id,
        new_role=data.role,
        performing_admin=current_super_admin,
    )


@router.delete(
    "/users/{user_id}",
    response_model=MessageResponse,
    status_code=status.HTTP_200_OK,
    summary="Delete user account (Strictly USERC / Super Admin only)",
)
async def delete_user(
    user_id: str,
    current_super_admin: User = Depends(require_roles(UserRole.USERC)),
    db: AsyncSession = Depends(get_db),
) -> MessageResponse:
    """Permanently delete user account."""
    await UserService.delete_user(
        db=db,
        target_user_id=user_id,
        performing_admin=current_super_admin,
    )
    return MessageResponse(message="User account deleted successfully.")
