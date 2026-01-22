from typing import Generic, List, Optional, TypeVar
from pydantic import BaseModel

T = TypeVar("T")

class Page(BaseModel, Generic[T]):
    items: List[T]
    next_cursor: Optional[str] = None
    total: Optional[int] = None
