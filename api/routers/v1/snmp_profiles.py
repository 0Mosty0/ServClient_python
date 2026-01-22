from fastapi import APIRouter, Depends, HTTPException, Query
from typing import List
from sqlalchemy.orm import Session

from api.deps import get_db
from api.schemas.snmp_profile import SnmpProfileCreate, SnmpProfileUpdate, SnmpProfileOut
from api.repositories.snmp_profile_repo import SnmpProfileRepository

router = APIRouter(prefix="/api/v1/snmp-profiles", tags=["snmp_profiles"])

@router.get("/", response_model=List[SnmpProfileOut])
def list_profiles(db: Session = Depends(get_db), limit: int = Query(default=100, le=500)):
    items = SnmpProfileRepository.list(db, limit=limit)
    return [SnmpProfileOut.model_validate(i.__dict__) for i in items]

@router.get("/{profile_id}", response_model=SnmpProfileOut)
def get_profile(profile_id: int, db: Session = Depends(get_db)):
    p = SnmpProfileRepository.get(db, profile_id)
    if not p:
        raise HTTPException(status_code=404, detail="Profile not found")
    return SnmpProfileOut.model_validate(p.__dict__)

@router.post("/", response_model=SnmpProfileOut)
def create_profile(payload: SnmpProfileCreate, db: Session = Depends(get_db)):
    p = SnmpProfileRepository.create(db, payload)
    return SnmpProfileOut.model_validate(p.__dict__)

@router.patch("/{profile_id}", response_model=SnmpProfileOut)
def update_profile(profile_id: int, payload: SnmpProfileUpdate, db: Session = Depends(get_db)):
    p = SnmpProfileRepository.get(db, profile_id)
    if not p:
        raise HTTPException(status_code=404, detail="Profile not found")
    p = SnmpProfileRepository.update(db, p, payload)
    return SnmpProfileOut.model_validate(p.__dict__)

@router.delete("/{profile_id}", status_code=204)
def delete_profile(profile_id: int, db: Session = Depends(get_db)):
    p = SnmpProfileRepository.get(db, profile_id)
    if not p:
        raise HTTPException(status_code=404, detail="Profile not found")
    SnmpProfileRepository.delete(db, p)
    return
