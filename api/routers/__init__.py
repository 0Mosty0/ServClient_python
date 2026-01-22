from fastapi import APIRouter
from .system import router as system_router
from .v1.devices import router as devices_router
from .v1.snmp_profiles import router as profiles_router

api_router = APIRouter()
api_router.include_router(system_router)       # /api/v1/health, /api/v1/version
api_router.include_router(devices_router)      # /api/v1/devices
api_router.include_router(profiles_router)     # /api/v1/snmp-profiles
