import logging
from pathlib import Path

from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi import Request
from sqlalchemy import inspect, text

from app.api.v1.analyze import router as analyze_router
from app.api.v1.assistant import router as assistant_router
from app.api.v1.score import router as score_router
from app.api.v1.threat_dna import router as threat_dna_router
from app.api.v1.threats import router as threats_router
from app.api.v1.qr import router as qr_router
from app.api.v1.message import router as message_router
from app.api.v1.phone import router as phone_router
from app.api.v1.deepfake import router as deepfake_router
from app.api.v1.auth_events import router as auth_events_router
from app.core.config import settings
from app.core.rate_limiter import check_rate_limit
from app.database.connection import check_database_connection

logging.basicConfig(level=logging.INFO)

app = FastAPI(
    title=settings.PROJECT_NAME,
    description=(
        "CyberGuard cybersecurity analysis API "
        "with rule-based detection and Gemini AI."
    ),
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.BACKEND_CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def limit_public_api_requests(request: Request, call_next):
    """Apply a per-client request limit to API routes before expensive work."""
    if request.url.path.startswith(settings.API_V1_STR):
        client_id = request.client.host if request.client else "unknown"
        if settings.PUBLIC_DEMO_MODE:
            # Render places the real client address first in X-Forwarded-For.
            forwarded_for = request.headers.get("x-forwarded-for", "")
            if forwarded_for:
                client_id = forwarded_for.split(",", 1)[0].strip() or client_id
        check_rate_limit(client_id, settings.RATE_LIMIT_PER_MINUTE)
    return await call_next(request)

app.include_router(
    analyze_router,
    prefix=settings.API_V1_STR,
    tags=["URL Analysis"],
)
app.include_router(
    message_router,
    prefix=settings.API_V1_STR,
    tags=["Message Scam Detection"],
)
app.include_router(
    phone_router,
    prefix=settings.API_V1_STR,
    tags=["Phone Number Analysis"],
)
app.include_router(
    deepfake_router,
    prefix=settings.API_V1_STR,
    tags=["Deepfake Media Validation"],
)
app.include_router(
    qr_router,
    prefix=settings.API_V1_STR,
    tags=["QR Code Analysis"],
)

app.include_router(
    threat_dna_router,
    prefix=settings.API_V1_STR,
    tags=["Threat DNA"],
)

app.include_router(
    assistant_router,
    prefix=settings.API_V1_STR,
    tags=["CyberGuard Assistant"],
)

app.include_router(
    score_router,
    prefix=settings.API_V1_STR,
    tags=["Security Score"],
)

app.include_router(
    threats_router,
    prefix=settings.API_V1_STR,
    tags=["Threat Records"],
)
app.include_router(
    auth_events_router,
    prefix=settings.API_V1_STR,
    tags=["Authentication Anomaly Detection"],
)


FRONTEND_DIR = Path(__file__).resolve().parents[2] / "frontend"

app.mount(
    "/assets",
    StaticFiles(directory=str(FRONTEND_DIR)),
    name="frontend-assets",
)


@app.on_event("startup")
def initialize_tables():
    """Create missing demo tables without preventing offline API startup."""
    if settings.PUBLIC_DEMO_MODE:
        logging.getLogger(__name__).info(
            "Public demo mode enabled; visitor analyses will not be persisted."
        )
        return
    try:
        import app.models  # noqa: F401
        from app.database.connection import Base, engine

        Base.metadata.create_all(bind=engine)
        # Add fields introduced after the first prototype schema was created.
        with engine.begin() as connection:
            columns = {column["name"] for column in inspect(engine).get_columns("threat_analyses")}
            if "evidence_json" not in columns:
                connection.execute(text(
                    "ALTER TABLE threat_analyses ADD COLUMN evidence_json TEXT NOT NULL DEFAULT '[]'"
                ))
            if "analysis_type" not in columns:
                connection.execute(text(
                    "ALTER TABLE threat_analyses ADD COLUMN analysis_type VARCHAR(80) NOT NULL DEFAULT 'rules_only'"
                ))
            event_columns = {column["name"] for column in inspect(engine).get_columns("security_events")}
            if "ai_provider" not in event_columns:
                connection.execute(text(
                    "ALTER TABLE security_events ADD COLUMN ai_provider VARCHAR(50) NOT NULL DEFAULT 'rules'"
                ))
            if "analysis_type" not in event_columns:
                connection.execute(text(
                    "ALTER TABLE security_events ADD COLUMN analysis_type VARCHAR(80) NOT NULL DEFAULT 'rules_only'"
                ))
    except Exception:
        logging.getLogger(__name__).exception(
            "Database unavailable during startup; persistence is disabled."
        )


@app.get("/", include_in_schema=False)
def home():
    index_file = FRONTEND_DIR / "index.html"

    if index_file.exists():
        return FileResponse(index_file)

    return {
        "success": True,
        "message": "CyberGuard API is running.",
        "docs": "/docs",
    }

@app.get("/health")
def health():
    if settings.PUBLIC_DEMO_MODE:
        return {"status": "healthy", "database": "disabled_public_demo"}
    database_connected = check_database_connection()

    return {
        "status": "healthy" if database_connected else "degraded",
        "database": (
            "connected" if database_connected else "disconnected"
        ),
    }
