from fastapi import APIRouter, Query

router = APIRouter()


@router.get("/")
async def list_controls(
    framework: str | None = Query(None, description="Filter by framework tag, e.g. CMMC-2.0-L2"),
    status: str | None = Query(None, description="Filter by compliance status"),
    limit: int = Query(50, le=200),
    offset: int = Query(0),
):
    # TODO: query Postgres via SQLAlchemy async session
    return {"items": [], "total": 0, "limit": limit, "offset": offset}


@router.get("/{scf_id}")
async def get_control(scf_id: str):
    # TODO: fetch single control record
    return {"scf_id": scf_id}
