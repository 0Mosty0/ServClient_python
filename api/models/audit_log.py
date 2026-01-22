from __future__ import annotations

from typing import Optional, Dict, Any, TYPE_CHECKING
from sqlalchemy import Integer, String, JSON, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship
from .base import Base, TimestampMixin

if TYPE_CHECKING : 
    from .users import User
class AuditLog(Base, TimestampMixin):
    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[Optional[int]] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    action: Mapped[str] = mapped_column(String(64), nullable=False)  # create|update|delete|login|...
    target_type: Mapped[Optional[str]] = mapped_column(String(64))
    target_id: Mapped[Optional[str]] = mapped_column(String(64))
    meta: Mapped[Optional[Dict[str, Any]]] = mapped_column("metadata", JSON)  # ← alias SQL

    user: Mapped[Optional["User"]] = relationship(back_populates="audit_logs")
