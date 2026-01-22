from fastapi import APIRouter, Depends, HTTPException, Query
from typing import List, Optional
from sqlalchemy.orm import Session

from api.deps import get_db
from api.schemas.device import DeviceCreate, DeviceUpdate, DeviceOut
from api.repositories.device_repo import DeviceRepository
from api.repositories.snmp_profile_repo import SnmpProfileRepository

router = APIRouter(prefix="/api/v1/devices", tags=["devices"])

@router.get("/", response_model=List[DeviceOut])
def list_devices(
    db: Session = Depends(get_db),
    q: Optional[str] = Query(default=None, description="search by name or IP"),
    limit: int = Query(default=100, le=500),
):
    items = DeviceRepository.list(db, q=q, limit=limit)
    return [DeviceOut.model_validate(i.__dict__) for i in items]

@router.get("/{device_id}", response_model=DeviceOut)
def get_device(device_id: int, db: Session = Depends(get_db)):
    d = DeviceRepository.get(db, device_id)
    if not d:
        raise HTTPException(status_code=404, detail="Device not found")
    return DeviceOut.model_validate(d.__dict__)

@router.post("/", response_model=DeviceOut)
def create_device(payload: DeviceCreate, db: Session = Depends(get_db)):
    # Vérifie l'existence du profil si fourni
    if payload.snmp_profile_id is not None:
        p = SnmpProfileRepository.get(db, payload.snmp_profile_id)
        if not p:
            raise HTTPException(status_code=400, detail="snmp_profile_id does not exist")

    try:
        d = DeviceRepository.create(db, payload)
    except ValueError as e:
        raise HTTPException(status_code=409, detail=str(e))
    return DeviceOut.model_validate(d.__dict__)

@router.patch("/{device_id}", response_model=DeviceOut)
def update_device(device_id: int, payload: DeviceUpdate, db: Session = Depends(get_db)):
    d = DeviceRepository.get(db, device_id)
    if not d:
        raise HTTPException(status_code=404, detail="Device not found")

    # si on change de profil, valider l'existence
    changes = payload.model_dump(exclude_unset=True)
    if "snmp_profile_id" in changes and changes["snmp_profile_id"] is not None:
        p = SnmpProfileRepository.get(db, changes["snmp_profile_id"])
        if not p:
            raise HTTPException(status_code=400, detail="snmp_profile_id does not exist")

    d = DeviceRepository.update(db, d, payload)
    return DeviceOut.model_validate(d.__dict__)

@router.delete("/{device_id}", status_code=204)
def delete_device(device_id: int, db: Session = Depends(get_db)):
    d = DeviceRepository.get(db, device_id)
    if not d:
        raise HTTPException(status_code=404, detail="Device not found")
    DeviceRepository.delete(db, d)
    return
