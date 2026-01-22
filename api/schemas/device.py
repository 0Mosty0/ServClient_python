from pydantic import BaseModel, Field, IPvAnyAddress
from typing import Optional, List
from datetime import datetime

# --------- Entrées ---------
class DeviceCreate(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    ip_address: IPvAnyAddress
    snmp_profile_id: Optional[int] = None
    location: Optional[str] = Field(default=None, max_length=100)
    tags: Optional[List[str]] = None
    enabled: bool = True

class DeviceUpdate(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=100)
    ip_address: Optional[IPvAnyAddress] = None
    snmp_profile_id: Optional[int] = None
    location: Optional[str] = Field(default=None, max_length=100)
    tags: Optional[List[str]] = None
    enabled: Optional[bool] = None

# --------- Sorties ---------
class DeviceOut(BaseModel):
    id: int
    name: str
    ip_address: str
    snmp_profile_id: Optional[int]
    location: Optional[str]
    tags: Optional[list[str]]
    enabled: bool
    created_at: datetime
