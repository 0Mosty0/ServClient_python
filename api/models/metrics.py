from datetime import datetime
from typing import Optional, TYPE_CHECKING
from sqlalchemy import Integer, String, Float, DateTime, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship
from .base import Base

if TYPE_CHECKING :
    from .devices import Device
class Metric(Base):
    __tablename__ = "metrics"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"), index=True, nullable=False)
    oid: Mapped[str] = mapped_column(String(255), index=True, nullable=False)
    value_str: Mapped[Optional[str]] = mapped_column(String(1024))
    value_num: Mapped[Optional[float]] = mapped_column(Float)
    polled_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)

    device: Mapped["Device"] = relationship(back_populates="metrics")
