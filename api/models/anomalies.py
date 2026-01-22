from __future__ import annotations
from datetime import datetime
from typing import Optional, Dict, Any, TYPE_CHECKING
from sqlalchemy import Integer, String, DateTime, Boolean, ForeignKey, JSON
from sqlalchemy.orm import Mapped, mapped_column, relationship
from .base import Base

if TYPE_CHECKING : 
    from .devices import Device
class Anomaly(Base):
    __tablename__ = "anomalies"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id", ondelete="SET NULL"))
    rule: Mapped[str] = mapped_column(String(128), nullable=False)
    details: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON)
    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    acked: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    device: Mapped[Optional["Device"]] = relationship(back_populates="anomalies")
