from sqlalchemy.orm import Session
from sqlalchemy import select
from typing import List, Optional
from api.models.snmp_profiles import SnmpProfiles
from api.schemas.snmp_profile import SnmpProfileCreate, SnmpProfileUpdate

class SnmpProfileRepository:
    """Accès DB pour 'snmp_profiles'."""

    @staticmethod
    def list(db: Session, limit: int = 100) -> List[SnmpProfiles]:
        stmt = select(SnmpProfiles).order_by(SnmpProfiles.id.desc()).limit(limit)
        return db.execute(stmt).scalars().all()

    @staticmethod
    def get(db: Session, profile_id: int) -> Optional[SnmpProfiles]:
        return db.get(SnmpProfiles, profile_id)

    @staticmethod
    def create(db: Session, data: SnmpProfileCreate) -> SnmpProfiles:
        obj = SnmpProfiles(**data.model_dump())
        db.add(obj)
        db.commit()
        db.refresh(obj)
        return obj

    @staticmethod
    def update(db: Session, profile: SnmpProfiles, data: SnmpProfileUpdate) -> SnmpProfiles:
        for field, value in data.model_dump(exclude_unset=True).items():
            setattr(profile, field, value)
        db.commit()
        db.refresh(profile)
        return profile

    @staticmethod
    def delete(db: Session, profile: SnmpProfiles) -> None:
        db.delete(profile)
        db.commit()
