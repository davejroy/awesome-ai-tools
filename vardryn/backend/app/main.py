import structlog
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.routers import evidence, controls, health

log = structlog.get_logger()

app = FastAPI(
    title="Vardryn Governance Intelligence Platform",
    version="0.1.0",
    docs_url="/docs" if True else None,  # Disable in prod via env guard
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://*.vardryn.com"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH"],
    allow_headers=["Authorization", "Content-Type"],
)

app.include_router(health.router)
app.include_router(evidence.router, prefix="/api/v1/evidence", tags=["evidence"])
app.include_router(controls.router, prefix="/api/v1/controls", tags=["controls"])


@app.on_event("startup")
async def startup():
    log.info("vardryn_api_started")
