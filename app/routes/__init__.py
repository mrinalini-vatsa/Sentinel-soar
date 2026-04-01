"""HTTP route modules."""

from fastapi import APIRouter

from app.routes import analyze, health, root

api_router = APIRouter()
api_router.include_router(root.router)
api_router.include_router(health.router)
api_router.include_router(analyze.router)

__all__ = ["api_router"]
