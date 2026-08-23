from fastapi import APIRouter, Depends, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_active_user, get_db
from app.models.user import User
from app.schemas.auth import LoginRequest, RefreshTokenRequest, RegisterRequest
from app.schemas.token import TokenResponse
from app.schemas.user import UserResponse
from app.services.auth_service import AuthService
from app.services.user_service import UserService

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post(
    "/register",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new user account",
    description="Public registration endpoint. Automatically assigns base persona role (USERA) to prevent privilege escalation.",
)
async def register(
    data: RegisterRequest,
    db: AsyncSession = Depends(get_db),
) -> User:
    """Register a new standard user account."""
    user = await UserService.register_user(db, data)
    return user


@router.post(
    "/login",
    response_model=TokenResponse,
    status_code=status.HTTP_200_OK,
    summary="User Login with Rate Limiting & Lockout",
    description=(
        "Authenticates user by username or email. Enforces max failed attempts (5) "
        "and temporary account lockout (15 minutes). Successful authentication resets lockout status."
    ),
)
async def login(
    data: LoginRequest,
    db: AsyncSession = Depends(get_db),
) -> TokenResponse:
    """Authenticate and obtain JWT access & refresh tokens."""
    _, token_response = await AuthService.authenticate_user(
        db=db,
        username_or_email=data.username_or_email,
        password=data.password,
    )
    return token_response


@router.post(
    "/refresh",
    response_model=TokenResponse,
    status_code=status.HTTP_200_OK,
    summary="Refresh Access Token",
    description="Exchange a valid JWT refresh token for a newly signed access token.",
)
async def refresh_token(
    data: RefreshTokenRequest,
    db: AsyncSession = Depends(get_db),
) -> TokenResponse:
    """Generate a new access token using a valid refresh token."""
    return await AuthService.refresh_tokens(db=db, refresh_token=data.refresh_token)


@router.get(
    "/me",
    response_model=UserResponse,
    status_code=status.HTTP_200_OK,
    summary="Get Current User Details",
    description="Returns profile details of the currently authenticated user.",
)
async def get_me(
    current_user: User = Depends(get_current_active_user),
) -> User:
    """Retrieve details for the active authenticated user."""
    return current_user
