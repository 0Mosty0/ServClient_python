from __future__ import annotations
import os, traceback
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException
from .telemetry.logging import log

DEV = os.getenv("APP_DEBUG", "0") == "1"

def install_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(StarletteHTTPException)
    async def http_exc(request: Request, exc: StarletteHTTPException):
        payload = {
            "detail": exc.detail,
            "code": "http_error",
            "meta": {"status": exc.status_code, "path": request.url.path},
        }
        log.warn("http_error", **payload["meta"], detail=payload["detail"])
        return JSONResponse(status_code=exc.status_code, content=payload)

    @app.exception_handler(RequestValidationError)
    async def validation_exc(request: Request, exc: RequestValidationError):
        payload = {
            "detail": "Validation error",
            "code": "validation_error",
            "meta": {"errors": exc.errors(), "path": request.url.path},
        }
        log.warn("validation_error", path=request.url.path, errors=exc.errors())
        return JSONResponse(status_code=422, content=payload)

    @app.exception_handler(Exception)
    async def unhandled_exc(request: Request, exc: Exception):
        payload = {
            "detail": "Internal server error",
            "code": "internal_error",
            "meta": {"path": request.url.path},
        }
        if DEV:
            payload["meta"]["traceback"] = traceback.format_exc(limit=10)
            payload["meta"]["error"] = str(exc)
        log.error("internal_error", path=request.url.path, error=str(exc))
        return JSONResponse(status_code=500, content=payload)
