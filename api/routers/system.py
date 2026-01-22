from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import text
from sqlalchemy.orm import Session
from api.deps import get_db

router = APIRouter(prefix="/api/v1", tags=["system"])

@router.get("/health")
def health():
    return {"status": "ok"}

@router.get("/version")
def version():
    return {"version": "0.1.0"}

@router.get("/db-ping")
def db_ping(db: Session = Depends(get_db)):
    try:
        db.execute(text("SELECT 1"))
        return {"db": "ok"}
    except Exception as e:
        # Ne renvoie pas de détails sensibles
        raise HTTPException(status_code=500, detail="DB connection failed")
