from typing import Optional
from pydantic import BaseModel
from app.models.enums import UserRole


class TokenPayload(BaseModel):
    """Payload decoded from JWT tokens."""
    sub: str  # User ID
    username: str
    email: str
    role: UserRole
    type: str  # "access" or "refresh"
    exp: int
    iat: int


class TokenResponse(BaseModel):
    """Authentication token response schema."""
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int
    role: UserRole
    user_id: str
    username: str
