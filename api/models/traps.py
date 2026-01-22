from datetime import datetime
from typing import Optional, List, TYPE_CHECKING
from sqlalchemy import Integer, String, DateTime, ForeignKey, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship
from .base import Base

if TYPE_CHECKING : 
    from .devices import Device
class Trap(Base):
    __tablename__ = "traps"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id", ondelete="SET NULL"))
    oid: Mapped[str] = mapped_column(String(255), index=True, nullable=False)
    severity: Mapped[Optional[str]] = mapped_column(String(32))  # info|warn|error|critical
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True, nullable=False)
    raw_pdu: Mapped[Optional[str]] = mapped_column(Text)

    device: Mapped[Optional["Device"]] = relationship(back_populates="traps")
    varbinds: Mapped[List["TrapVarbind"]] = relationship(back_populates="trap", cascade="all, delete-orphan")


from typing import Optional
from sqlalchemy import Integer, String, ForeignKey, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship
from .base import Base

class TrapVarbind(Base):
    __tablename__ = "trap_varbinds"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    trap_id: Mapped[int] = mapped_column(ForeignKey("traps.id", ondelete="CASCADE"), nullable=False, index=True)
    oid: Mapped[str] = mapped_column(String(255), nullable=False)
    type: Mapped[Optional[str]] = mapped_column(String(64))
    value: Mapped[Optional[str]] = mapped_column(Text)

    trap: Mapped["Trap"] = relationship(back_populates="varbinds")
