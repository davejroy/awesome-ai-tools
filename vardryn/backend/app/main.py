import structlog
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import settings
from app.routers import evidence, controls, health

log = structlog.get_logger()

# OpenAPI docs are exposed only outside production.
_docs_enabled = settings.environment != "prod"

app = FastAPI(
    title="Vardryn Governance Intelligence Platform",
    version="0.1.0",
    docs_url="/docs" if _docs_enabled else None,
    redoc_url="/redoc" if _docs_enabled else None,
    openapi_url="/openapi.json" if _docs_enabled else None,
)

# Starlette's CORS `allow_origins` treats each entry as a LITERAL origin — a
# "https://*.vardryn.com" wildcard would never match app.vardryn.com. Use a
# regex for the subdomain pattern (plus localhost for local dev).
app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=r"https://([a-z0-9-]+\.)*vardryn\.com|http://localhost(:\d+)?",
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
