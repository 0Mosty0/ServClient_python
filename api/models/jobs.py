from typing import List, Optional, TYPE_CHECKING
from sqlalchemy import String, Integer, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship
from .base import Base, TimestampMixin

if TYPE_CHECKING:
    from .devices import Device

class Job(Base, TimestampMixin):
    __tablename__ = "jobs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"), nullable=False)
    kind: Mapped[str] = mapped_column(String(32), nullable=False)  # poll|get|getbulk|set|discover
    status: Mapped[str] = mapped_column(String(32), default="pending", nullable=False)  # pending|running|done|error
    note: Mapped[Optional[str]] = mapped_column(String(255))

    device: Mapped["Device"] = relationship(back_populates="jobs")
    oids: Mapped[List["JobOid"]] = relationship(back_populates="job", cascade="all, delete-orphan")


from sqlalchemy import String, Integer, ForeignKey, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship
from .base import Base

class JobOid(Base):
    __tablename__ = "job_oids"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    job_id: Mapped[int] = mapped_column(ForeignKey("jobs.id", ondelete="CASCADE"), nullable=False)
    oid: Mapped[str] = mapped_column(String(255), nullable=False)
    expected_type: Mapped[Optional[str]] = mapped_column(String(32))
    note: Mapped[Optional[str]] = mapped_column(Text)

    job: Mapped["Job"] = relationship(back_populates="oids")
