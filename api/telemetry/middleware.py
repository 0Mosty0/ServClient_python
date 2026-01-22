from __future__ import annotations
import time, uuid
from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from .logging import log

def _rid() -> str:
    return uuid.uuid4().hex

class RequestContextMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        rid = request.headers.get("X-Request-ID") or _rid()
        start = time.perf_counter()
        logger = log.bind(req_id=rid, path=request.url.path, method=request.method)
        try:
            response = await call_next(request)
            ms = round((time.perf_counter() - start) * 1000, 1)
            logger.info("request.done", status=response.status_code, ms=ms)
            response.headers["X-Request-ID"] = rid
            return response
        except Exception as exc:
            ms = round((time.perf_counter() - start) * 1000, 1)
            logger.error("request.error", ms=ms, error=str(exc))
            raise
