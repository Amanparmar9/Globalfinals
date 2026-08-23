from typing import List, Optional, Tuple
from sqlalchemy import select, or_, func
from sqlalchemy.ext.asyncio import AsyncSession
from fastapi import HTTPException, status

from app.config import settings
from app.models.enums import UserRole
from app.models.user import User
from app.schemas.auth import RegisterRequest
from app.schemas.user import (
    UserUpdateMe,
    AdminUserUpdate,
    PasswordChangeRequest,
)
from app.utils.security import hash_password, verify_password


class UserService:
    @staticmethod
    async def get_by_id(db: AsyncSession, user_id: str) -> Optional[User]:
        """Fetch user by primary key ID."""
        query = select(User).where(User.id == user_id)
        result = await db.execute(query)
        return result.scalar_one_or_none()

    @staticmethod
    async def get_by_email(db: AsyncSession, email: str) -> Optional[User]:
        """Fetch user by lowercase email."""
        query = select(User).where(User.email == email.strip().lower())
        result = await db.execute(query)
        return result.scalar_one_or_none()

    @staticmethod
    async def get_by_username(db: AsyncSession, username: str) -> Optional[User]:
        """Fetch user by lowercase username."""
        query = select(User).where(User.username == username.strip().lower())
        result = await db.execute(query)
        return result.scalar_one_or_none()

    @staticmethod
    async def register_user(
        db: AsyncSession,
        data: RegisterRequest,
    ) -> User:
        """
        Register a new user account. Always assigns base role (USERA)
        to strictly prevent privilege escalation.
        """
        # Check if email is already taken
        if await UserService.get_by_email(db, data.email):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="A user with this email address already exists.",
            )

        # Check if username is already taken
        if await UserService.get_by_username(db, data.username):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="This username is already taken.",
            )

        new_user = User(
            email=data.email.strip().lower(),
            username=data.username.strip().lower(),
            full_name=data.full_name.strip() if data.full_name else None,
            hashed_password=hash_password(data.password),
            role=UserRole.USERA,  # Default to base user role
            is_active=True,
            is_verified=False,
            failed_login_attempts=0,
            locked_until=None,
        )
        db.add(new_user)
        await db.commit()
        await db.refresh(new_user)
        return new_user

    @staticmethod
    async def update_self_profile(
        db: AsyncSession,
        user: User,
        data: UserUpdateMe,
    ) -> User:
        """Update current authenticated user's profile info."""
        if data.email and data.email.strip().lower() != user.email:
            existing = await UserService.get_by_email(db, data.email)
            if existing and existing.id != user.id:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="This email address is already in use by another account.",
                )
            user.email = data.email.strip().lower()

        if data.full_name is not None:
            user.full_name = data.full_name.strip()

        await db.commit()
        await db.refresh(user)
        return user

    @staticmethod
    async def change_password(
        db: AsyncSession,
        user: User,
        data: PasswordChangeRequest,
    ) -> None:
        """Change authenticated user's password after verifying existing password."""
        if not verify_password(data.current_password, user.hashed_password):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Incorrect current password.",
            )

        if data.current_password == data.new_password:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="New password must be different from current password.",
            )

        user.hashed_password = hash_password(data.new_password)
        # Reset any failed attempts
        user.failed_login_attempts = 0
        user.locked_until = None
        await db.commit()

    @staticmethod
    async def list_users(
        db: AsyncSession,
        skip: int = 0,
        limit: int = 50,
        role: Optional[UserRole] = None,
        search: Optional[str] = None,
    ) -> Tuple[List[User], int]:
        """List users with pagination, role filtering, and search."""
        query = select(User)
        count_query = select(func.count(User.id))

        if role:
            query = query.where(User.role == role)
            count_query = count_query.where(User.role == role)

        if search:
            search_pattern = f"%{search.strip().lower()}%"
            filter_condition = or_(
                User.username.ilike(search_pattern),
                User.email.ilike(search_pattern),
                User.full_name.ilike(search_pattern),
            )
            query = query.where(filter_condition)
            count_query = count_query.where(filter_condition)

        total_res = await db.execute(count_query)
        total = total_res.scalar_one()

        query = query.order_by(User.created_at.desc()).offset(skip).limit(limit)
        res = await db.execute(query)
        users = list(res.scalars().all())
        return users, total

    @staticmethod
    async def admin_update_user(
        db: AsyncSession,
        target_user_id: str,
        data: AdminUserUpdate,
        performing_admin: User,
    ) -> User:
        """Update user properties (active status, verification) by an admin."""
        target_user = await UserService.get_by_id(db, target_user_id)
        if not target_user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found.",
            )

        # Hierarchy protection: Cannot modify someone of equal or higher role unless you are USERC
        if performing_admin.role != UserRole.USERC:
            if target_user.role.hierarchy_level >= performing_admin.role.hierarchy_level:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="You do not have permission to modify users of equal or higher role.",
                )

        if data.is_active is not None:
            target_user.is_active = data.is_active
        if data.is_verified is not None:
            target_user.is_verified = data.is_verified
        if data.full_name is not None:
            target_user.full_name = data.full_name.strip()

        await db.commit()
        await db.refresh(target_user)
        return target_user

    @staticmethod
    async def unlock_user(
        db: AsyncSession,
        target_user_id: str,
        performing_admin: User,
    ) -> User:
        """Unlock a locked user account and reset failed login attempts."""
        target_user = await UserService.get_by_id(db, target_user_id)
        if not target_user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found.",
            )

        if performing_admin.role != UserRole.USERC:
            if target_user.role.hierarchy_level >= performing_admin.role.hierarchy_level:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Cannot unlock users of equal or higher role.",
                )

        target_user.failed_login_attempts = 0
        target_user.locked_until = None
        await db.commit()
        await db.refresh(target_user)
        return target_user

    @staticmethod
    async def update_user_role(
        db: AsyncSession,
        target_user_id: str,
        new_role: UserRole,
        performing_admin: User,
    ) -> User:
        """
        Update user role. Only USERC can assign roles or change permissions.
        """
        if performing_admin.role != UserRole.USERC:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Only USERC (Super Administrator) can modify user roles.",
            )

        target_user = await UserService.get_by_id(db, target_user_id)
        if not target_user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found.",
            )

        # Prevent a super admin from demoting themselves if they are the only USERC
        if target_user.id == performing_admin.id and new_role != UserRole.USERC:
            query = select(func.count(User.id)).where(User.role == UserRole.USERC)
            res = await db.execute(query)
            count = res.scalar_one()
            if count <= 1:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Cannot demote the last remaining USERC (Super Admin).",
                )

        target_user.role = new_role
        await db.commit()
        await db.refresh(target_user)
        return target_user

    @staticmethod
    async def delete_user(
        db: AsyncSession,
        target_user_id: str,
        performing_admin: User,
    ) -> None:
        """Delete user account (USERC only)."""
        if performing_admin.role != UserRole.USERC:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Only USERC (Super Administrator) can delete accounts.",
            )

        target_user = await UserService.get_by_id(db, target_user_id)
        if not target_user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found.",
            )

        if target_user.id == performing_admin.id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cannot delete your own account.",
            )

        await db.delete(target_user)
        await db.commit()

    @staticmethod
    async def seed_initial_super_admin(db: AsyncSession) -> Optional[User]:
        """
        Seeds initial USERC super admin on startup if no USERC exists in database.
        """
        query = select(User).where(User.role == UserRole.USERC)
        result = await db.execute(query)
        existing_super_admin = result.scalar_one_or_none()

        if existing_super_admin:
            return None

        # Check if email/username already taken
        if await UserService.get_by_email(db, settings.SUPER_ADMIN_EMAIL):
            return None
        if await UserService.get_by_username(db, settings.SUPER_ADMIN_USERNAME):
            return None

        super_admin = User(
            email=settings.SUPER_ADMIN_EMAIL.strip().lower(),
            username=settings.SUPER_ADMIN_USERNAME.strip().lower(),
            full_name="System Super Administrator",
            hashed_password=hash_password(settings.SUPER_ADMIN_PASSWORD),
            role=UserRole.USERC,
            is_active=True,
            is_verified=True,
            failed_login_attempts=0,
            locked_until=None,
        )
        db.add(super_admin)
        await db.commit()
        await db.refresh(super_admin)
        return super_admin
