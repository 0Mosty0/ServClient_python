from typing import Optional, List, TYPE_CHECKING
from sqlalchemy import String, Integer, Boolean
from sqlalchemy.orm import Mapped, mapped_column, relationship
from .base import Base, TimestampMixin

if TYPE_CHECKING : 
    from .devices import Device
class SnmpProfiles(Base, TimestampMixin):
    __tablename__ = "snmp_profiles"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(128), unique=True, nullable=False, index=True)
    version: Mapped[str] = mapped_column(String(8), default="v2c", nullable=False)  # v1|v2c|v3

    # v1/v2c
    community: Mapped[Optional[str]] = mapped_column(String(255))

    # v3
    security_level: Mapped[Optional[str]] = mapped_column(String(16))  # noAuthNoPriv|authNoPriv|authPriv
    username: Mapped[Optional[str]] = mapped_column(String(128))
    auth_protocol: Mapped[Optional[str]] = mapped_column(String(16))  # MD5|SHA
    auth_key: Mapped[Optional[str]] = mapped_column(String(255))
    priv_protocol: Mapped[Optional[str]] = mapped_column(String(16))  # DES|AES
    priv_key: Mapped[Optional[str]] = mapped_column(String(255))

    timeout_ms: Mapped[int] = mapped_column(Integer, default=2000, nullable=False)
    retries: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    port: Mapped[int] = mapped_column(Integer, default=161, nullable=False)

    devices: Mapped[List["Device"]] = relationship(back_populates="snmp_profile")
