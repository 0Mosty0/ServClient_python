from sqlalchemy.orm import Session
from sqlalchemy import select
from typing import List, Optional
from api.models.devices import Device
from api.schemas.device import DeviceCreate, DeviceUpdate

class DeviceRepository:
    """Couche d'accès aux données pour la table 'devices'."""

    @staticmethod
    def list(db: Session, q: Optional[str] = None, limit: int = 100) -> List[Device]:
        stmt = select(Device).order_by(Device.created_at.desc()).limit(limit)
        if q:
            stmt = stmt.where((Device.name.ilike(f"%{q}%")) | (Device.ip_address == q))
        return db.execute(stmt).scalars().all()

    @staticmethod
    def get(db: Session, device_id: int) -> Optional[Device]:
        return db.get(Device, device_id)

    @staticmethod
    def create(db: Session, data: DeviceCreate) -> Device:
        # unicité “logique” IP (à toi d’ajouter une contrainte unique si tu veux)
        existing = db.execute(select(Device).where(Device.ip_address == str(data.ip_address))).scalar_one_or_none()
        if existing:
            raise ValueError("Device with this IP already exists")
        obj = Device(
            name=data.name,
            ip_address=str(data.ip_address),
            snmp_profile_id=data.snmp_profile_id,
            location=data.location,
            tags=data.tags,
            enabled=data.enabled,
        )
        db.add(obj)
        db.commit()
        db.refresh(obj)
        return obj

    @staticmethod
    def update(db: Session, device: Device, data: DeviceUpdate) -> Device:
        for field, value in data.model_dump(exclude_unset=True).items():
            if field == "ip_address" and value is not None:
                value = str(value)
            setattr(device, field, value)
        db.commit()
        db.refresh(device)
        return device

    @staticmethod
    def delete(db: Session, device: Device) -> None:
        db.delete(device)
        db.commit()
