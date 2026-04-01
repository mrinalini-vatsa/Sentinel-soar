"""
SentinelSOAR — FastAPI application entry.
"""

from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, status
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from app.routes import api_router
from app.utils.logger import setup_logging


@asynccontextmanager
async def lifespan(app: FastAPI):
    setup_logging()
    yield


app = FastAPI(
    title="SentinelSOAR",
    description="AI-powered SOAR system for IP threat analysis",
    version="1.0.0",
    lifespan=lifespan,
)


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """Consistent JSON for invalid bodies (e.g. malformed IP)."""
    errors = exc.errors()
    first = errors[0] if errors else {}
    msg = first.get("msg", "Validation error")
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content=jsonable_encoder(
            {
                "detail": "Request validation failed",
                "errors": errors,
                "message": msg,
            }
        ),
    )


app.include_router(api_router)
