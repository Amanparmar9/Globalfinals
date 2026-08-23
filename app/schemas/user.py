import re
import datetime
from typing import Optional
from pydantic import BaseModel, EmailStr, Field, field_validator, ConfigDict
from app.models.enums import UserRole


class UserResponse(BaseModel):
    """Schema representing user data returned by API endpoints."""
    model_config = ConfigDict(from_attributes=True)

    id: str
    email: str
    username: str
    full_name: Optional[str] = None
    role: UserRole
    is_active: bool
    is_verified: bool
    is_locked: bool
    remaining_lockout_seconds: int
    failed_login_attempts: int
    last_login_at: Optional[datetime.datetime] = None
    created_at: datetime.datetime
    updated_at: datetime.datetime


class UserUpdateMe(BaseModel):
    """Schema for users updating their own profile."""
    full_name: Optional[str] = Field(None, max_length=100)
    email: Optional[EmailStr] = None


class AdminUserUpdate(BaseModel):
    """Schema for administrators updating user status."""
    is_active: Optional[bool] = None
    is_verified: Optional[bool] = None
    full_name: Optional[str] = None


class UserRoleUpdate(BaseModel):
    """Schema for elevated role assignment."""
    role: UserRole = Field(..., description="Target role: USERA, USERB, or USERC")


class PasswordChangeRequest(BaseModel):
    """Schema for changing password when authenticated."""
    current_password: str = Field(..., description="Current password")
    new_password: str = Field(..., min_length=8, max_length=128, description="New strong password")

    @field_validator("new_password")
    @classmethod
    def validate_new_password_strength(cls, v: str) -> str:
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters long")
        if not re.search(r"[A-Z]", v):
            raise ValueError("Password must contain at least one uppercase letter")
        if not re.search(r"[a-z]", v):
            raise ValueError("Password must contain at least one lowercase letter")
        if not re.search(r"\d", v):
            raise ValueError("Password must contain at least one number")
        return v
