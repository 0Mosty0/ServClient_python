from datetime import datetime
from typing import Optional, List, TYPE_CHECKING

from sqlalchemy import String, Integer, DateTime, Boolean
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base, TimestampMixin

if TYPE_CHECKING : 
    from .audit_log import AuditLog
class User(Base, TimestampMixin):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    full_name: Mapped[Optional[str]] = mapped_column(String(255))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    role: Mapped[str] = mapped_column(String(50), default="read", nullable=False)  # read|ops|admin

    audit_logs: Mapped[List["AuditLog"]] = relationship(back_populates="user")
