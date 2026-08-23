import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import settings
from app.db.session import engine, init_db
from app.middleware.error_handler import setup_exception_handlers
from app.routes import api_router
from app.services.user_service import UserService
from app.db.session import AsyncSessionLocal

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("app.main")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifespan context manager for startup and shutdown events.
    """
    logger.info("Starting up application...")
    try:
        # Create database tables if they do not exist
        await init_db()
        logger.info("Database schema initialized successfully.")

        # Seed initial USERC (Super Admin) if configured
        async with AsyncSessionLocal() as session:
            super_admin = await UserService.seed_initial_super_admin(session)
            if super_admin:
                logger.info(
                    f"Seeded initial Super Admin account: {super_admin.email} (Role: {super_admin.role.value})"
                )
    except Exception as e:
        logger.error(f"Error during startup initialization: {e}", exc_info=True)

    yield

    logger.info("Shutting down application...")
    await engine.dispose()
    logger.info("Database engine connections closed.")


app = FastAPI(
    title=settings.APP_NAME,
    description="Production-grade Role-Based Authentication & Authorization (RBAC) System with Persona Roles (USERA, USERB, USERC).",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

# Setup CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Setup Global Exception Handlers
setup_exception_handlers(app)

# Mount all routes under /api
app.include_router(api_router, prefix=settings.API_PREFIX)


@app.get("/health", tags=["Health"])
async def health_check():
    """Health check endpoint for monitoring."""
    return {
        "status": "healthy",
        "app": settings.APP_NAME,
        "environment": settings.ENVIRONMENT,
    }


@app.get("/", tags=["Root"])
async def root():
    """Root endpoint providing quick navigation links."""
    return {
        "message": f"Welcome to {settings.APP_NAME} API",
        "docs": "/docs",
        "health": "/health",
        "api_prefix": settings.API_PREFIX,
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
