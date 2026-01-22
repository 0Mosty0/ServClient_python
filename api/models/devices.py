from datetime import datetime
from typing import Optional, List, TYPE_CHECKING
from sqlalchemy import String, Integer, ForeignKey, Text
from sqlalchemy.dialects.postgresql import ARRAY, TEXT
from sqlalchemy.orm import Mapped, mapped_column, relationship
from .base import Base, TimestampMixin

if TYPE_CHECKING:
    from .snmp_profiles import SnmpProfile
    from .jobs import Job
    from .metrics import Metric
    from .traps import Trap
    from .anomalies import Anomaly

class Device(Base, TimestampMixin):
    __tablename__ = "devices"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(128), index=True, nullable=False)
    hostname: Mapped[str] = mapped_column(String(255), index=True, nullable=False)
    ip_address: Mapped[Optional[str]] = mapped_column(String(64))
    vendor: Mapped[Optional[str]] = mapped_column(String(64))
    model: Mapped[Optional[str]] = mapped_column(String(64))
    tags: Mapped[Optional[List[str]]] = mapped_column(ARRAY(TEXT), default=list)

    snmp_profile_id: Mapped[int] = mapped_column(ForeignKey("snmp_profiles.id", ondelete="RESTRICT"), nullable=False)
    snmp_profile: Mapped["SnmpProfile"] = relationship(back_populates="devices")

    jobs: Mapped[List["Job"]] = relationship(back_populates="device", cascade="all, delete-orphan")
    metrics: Mapped[List["Metric"]] = relationship(back_populates="device", cascade="all, delete-orphan")
    traps: Mapped[List["Trap"]] = relationship(back_populates="device", cascade="all, delete-orphan")
    anomalies: Mapped[List["Anomaly"]] = relationship(back_populates="device", cascade="all, delete-orphan")
