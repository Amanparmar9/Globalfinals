from fastapi import APIRouter, Depends, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_active_user, get_db
from app.models.user import User
from app.schemas.auth import MessageResponse
from app.schemas.user import PasswordChangeRequest, UserResponse, UserUpdateMe
from app.services.user_service import UserService

router = APIRouter(prefix="/users", tags=["Users"])


@router.get(
    "/me",
    response_model=UserResponse,
    status_code=status.HTTP_200_OK,
    summary="Get user profile",
)
async def get_profile(
    current_user: User = Depends(get_current_active_user),
) -> User:
    """Retrieve self profile details."""
    return current_user


@router.patch(
    "/me",
    response_model=UserResponse,
    status_code=status.HTTP_200_OK,
    summary="Update user profile",
)
async def update_profile(
    data: UserUpdateMe,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
) -> User:
    """Update profile information (e.g. full name, email)."""
    return await UserService.update_self_profile(db=db, user=current_user, data=data)


@router.post(
    "/me/change-password",
    response_model=MessageResponse,
    status_code=status.HTTP_200_OK,
    summary="Change password",
)
async def change_password(
    data: PasswordChangeRequest,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
) -> MessageResponse:
    """Update password with verification of current password."""
    await UserService.change_password(db=db, user=current_user, data=data)
    return MessageResponse(message="Password successfully updated.")
