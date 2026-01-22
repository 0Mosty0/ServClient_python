from __future__ import annotations
import logging, os, sys
import structlog

def is_debug() -> bool:
    return os.getenv("APP_DEBUG", "0") == "1"

def configure_logging() -> None:
    level = logging.DEBUG if is_debug() else logging.INFO

    # Root logger (toutes libs redirigent ici)
    root = logging.getLogger()
    root.handlers.clear()
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter("%(message)s"))
    root.addHandler(handler)
    root.setLevel(level)

    # Calmer un peu le bruit
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("watchfiles").setLevel(logging.WARNING)
    logging.getLogger("asyncio").setLevel(logging.WARNING)
    # SQLAlchemy: verbeux seulement en debug
    logging.getLogger("sqlalchemy.engine").setLevel(logging.INFO if is_debug() else logging.WARNING)
    logging.getLogger("sqlalchemy.pool").setLevel(logging.WARNING)

    structlog.configure(
        processors=[
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(level),
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )

log = structlog.get_logger()
