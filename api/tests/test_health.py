import pytest
from httpx import AsyncClient
from api.main import app

@pytest.mark.asyncio
async def test_health_ok():
    async with AsyncClient(app=app, base_url="http://test") as ac:
        r = await ac.get("/api/v1/health")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}
