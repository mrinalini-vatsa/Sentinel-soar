"""Root route."""

from fastapi import APIRouter

router = APIRouter(tags=["system"])


@router.get("/")
async def root():
    return {"message": "SentinelSOAR API is running"}
