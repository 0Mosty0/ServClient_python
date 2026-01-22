from pydantic import BaseModel, Field
from typing import List, Optional, Literal

class VarBind(BaseModel):
    oid: str
    name: Optional[str] = None
    type: str
    value: str | int | float | bool | None = None
    enum: Optional[str] = None

class Endpoint(BaseModel):
    ip: str
    port: int

class Frame(BaseModel):
    id: str
    timestamp: str
    src: Endpoint
    dst: Endpoint
    version: Literal[1,2,3]
    pdu_type: Literal["get","getnext","getbulk","response","set","trap"]
    request_id: Optional[int]
    community: Optional[str] = None
    security_user: Optional[str] = None
    varbinds: List[VarBind]
    length: int
    tags: List[str] = []
    anomalies: List[str] = []
