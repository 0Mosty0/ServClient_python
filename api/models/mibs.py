from typing import Optional, List
from sqlalchemy import String, Integer, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship
from .base import Base, TimestampMixin

class Mib(Base, TimestampMixin):
    __tablename__ = "mibs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(128), unique=True, nullable=False, index=True)
    filename: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text)
