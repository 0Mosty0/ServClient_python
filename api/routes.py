from fastapi import APIRouter
from . import __version__, __app_name__

router = APIRouter(prefix="/api/v1", tags=["system"])

@router.get("/health")
def health():
    return {"status": "ok"}

@router.get("/version")
def version():
    return {"name": __app_name__, "version": __version__}


