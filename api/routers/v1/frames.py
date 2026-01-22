from fastapi import APIRouter, Depends, UploadFile, File, Query
from typing import Optional, List
from ...schemas.frame import Frame
from ...schemas.pagination import Page
from ...services.capture_service import CaptureService
from ...services.import_export_service import ImportExportService
from ...ws.sockets import manager

router = APIRouter(prefix="/frames")

@router.get("", response_model=Page[Frame])
async def list_frames(
    pdu: Optional[str] = Query(None),
    version: Optional[int] = Query(None),
    ip_src: Optional[str] = None,
    ip_dst: Optional[str] = None,
    oid_contains: Optional[str] = None,
    time_from: Optional[str] = None,
    time_to: Optional[str] = None,
    limit: int = 100,
    cursor: Optional[str] = None,
    svc: CaptureService = Depends(CaptureService.dep),
):
    return await svc.search(pdu, version, ip_src, ip_dst, oid_contains, time_from, time_to, limit, cursor)

@router.get("/{frame_id}", response_model=Frame)
async def get_frame(frame_id: str, svc: CaptureService = Depends(CaptureService.dep)):
    return await svc.get(frame_id)

@router.post("/import")
async def import_frames(
    file: UploadFile = File(...),
    mode: str = Query("json", regex="^(json|ndjson|pcap)$"),
    imp: ImportExportService = Depends(ImportExportService.dep),
):
    # pcap traité côté serveur; json/ndjson parse et renvoie un résumé
    count = await imp.import_file(file, mode)
    return {"imported": count}

@router.post("/export")
async def export_frames(
    fmt: str = Query("ndjson", regex="^(json|ndjson|csv)$"),
    filter: Optional[str] = None,
    imp: ImportExportService = Depends(ImportExportService.dep),
):
    return await imp.export_stream(fmt=fmt, filter=filter)  # StreamingResponse
