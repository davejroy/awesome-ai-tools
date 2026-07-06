from fastapi import APIRouter, File, Form, HTTPException, UploadFile, status

from app.services import evidence_service

router = APIRouter()

MAX_UPLOAD_BYTES = 50 * 1024 * 1024  # 50 MB


@router.post("/upload", status_code=status.HTTP_201_CREATED)
async def upload_evidence(
    file: UploadFile = File(...),
    control_id: str = Form(...),
    uploaded_by: str = Form(...),
):
    file_bytes = await file.read()

    if len(file_bytes) > MAX_UPLOAD_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"File exceeds {MAX_UPLOAD_BYTES // (1024*1024)} MB limit",
        )

    record = await evidence_service.upload_evidence(
        file_bytes=file_bytes,
        filename=file.filename or "unknown",
        control_id=control_id,
        uploaded_by=uploaded_by,
    )

    return record


@router.get("/{evidence_id}/verify")
async def verify_evidence(evidence_id: str):
    # TODO: load record from DB, recompute digest from GCS object, call kms_service.verify_signature
    raise HTTPException(status_code=501, detail="Not yet implemented")
