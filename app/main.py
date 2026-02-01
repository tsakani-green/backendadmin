# backend/app/main.py

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import logging
from datetime import datetime, timezone

from .core.config import settings
from .api import auth, invoices, files, analytics, reports, admin, sunsynk, gemini_ai
from .api.recent_activities import router as recent_activities_router
from .api.assets_sunsynk import router as assets_sunsynk_router
from .api.assets import router as projects_router
from .api.meters import router as meters_router
from .services.egauge_poller import start_egauge_scheduler
from .services.egauge_client import diagnose_egauge_connection

# Configure logging
logging.basicConfig(
    level=logging.DEBUG if settings.DEBUG else logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="ESG Dashboard API",
    version="1.0.0",
    description="API for ESG Dashboard with eGauge integration",
    docs_url="/docs" if settings.DEBUG else None,
    redoc_url="/redoc" if settings.DEBUG else None,
)

# -------------------------------------------------------------------
# Global exception handler (helps debug 500s cleanly)
# -------------------------------------------------------------------
@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    logger.exception(f"Unhandled exception on {request.method} {request.url}")
    return JSONResponse(
        status_code=500,
        content={
            "detail": "Internal server error",
            "path": str(request.url.path),
            "method": request.method,
            "error": str(exc) if settings.DEBUG else None,
        },
    )

# -------------------------------------------------------------------
# CORS middleware (Render/Vite safe)
# -------------------------------------------------------------------
def _build_cors_origins() -> list[str]:
    base = [
        # Vite default dev
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        # Other dev ports you used
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:3001",
        "http://127.0.0.1:3001",
        "http://localhost:3002",
        "http://127.0.0.1:3002",
        "http://localhost:3008",
        "http://127.0.0.1:3008",
    ]

    extra = []
    try:
        extra = settings.get_cors_origins()  # already list[str]
    except Exception as e:
        logger.warning(f"Failed to parse CORS_ORIGINS: {e}")
        extra = []

    # Always include FRONTEND_URL if set (Render static site)
    if getattr(settings, "FRONTEND_URL", ""):
        extra.append(settings.FRONTEND_URL.strip())

    merged: list[str] = []
    for origin in base + extra:
        origin = (origin or "").strip()
        if origin and origin not in merged:
            merged.append(origin)

    return merged


cors_origins = _build_cors_origins()
logger.info(f"CORS origins configured: {cors_origins}")

app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -------------------------------------------------------------------
# Routers
# -------------------------------------------------------------------
app.include_router(auth.router, prefix="/api/auth", tags=["auth"])
app.include_router(admin.router, prefix="/api/admin", tags=["admin"])
app.include_router(sunsynk.router, prefix="/api/sunsynk", tags=["sunsynk"])
app.include_router(assets_sunsynk_router, prefix="/api/assets", tags=["assets-sunsynk"])
app.include_router(invoices.router, tags=["invoices"])
app.include_router(files.router, prefix="/api/files", tags=["files"])
app.include_router(projects_router, prefix="/api/assets", tags=["assets"])
app.include_router(meters_router, prefix="/api/meters", tags=["meters"])
app.include_router(analytics.router, prefix="/api/analytics", tags=["analytics"])
app.include_router(reports.router, prefix="/api/reports", tags=["reports"])
app.include_router(gemini_ai.router, tags=["Gemini AI"])
app.include_router(recent_activities_router, tags=["recent-activities"])

scheduler = None


def _dump_routes():
    if not settings.DEBUG:
        return

    print("\n" + "=" * 60)
    print("REGISTERED ROUTES")
    print("=" * 60)

    routes_by_prefix = {}
    for route in app.routes:
        path = getattr(route, "path", "")
        methods = ",".join(sorted(getattr(route, "methods", []) or []))
        name = getattr(route, "name", "")

        prefix = "/".join(path.split("/")[:3]) if len(path.split("/")) > 2 else "Other"
        routes_by_prefix.setdefault(prefix, []).append(f"{methods:15} {path:45} -> {name}")

    for prefix in sorted(routes_by_prefix.keys()):
        print(f"\n{prefix}:")
        for route in sorted(routes_by_prefix[prefix]):
            print(f"  {route}")

    print("\n" + "=" * 60)
    print("END ROUTES")
    print("=" * 60 + "\n")


async def _run_startup_diagnostics():
    try:
        if not settings.EGAUGE_BASE_URL:
            return
        logger.info("Running eGauge connection diagnostics...")
        results = await diagnose_egauge_connection(settings.EGAUGE_BASE_URL)

        working = [r for r in results if r.get("status") == 200]
        errors = [r for r in results if r.get("error")]

        logger.info(f"Diagnostic complete: {len(working)} working endpoints, {len(errors)} errors")

        if not working:
            logger.error("No working eGauge endpoints found! Check configuration.")
    except Exception as e:
        logger.error(f"Startup diagnostic failed: {e}")


@app.on_event("startup")
async def on_startup():
    global scheduler

    logger.info("Starting ESG Dashboard API...")

    # Start eGauge scheduler (safe)
    try:
        scheduler = start_egauge_scheduler()
        logger.info("eGauge poller scheduler started")
    except Exception as e:
        logger.warning(f"eGauge scheduler not started: {e}")

    if settings.DEBUG:
        await _run_startup_diagnostics()
        _dump_routes()

    logger.info(f"Application startup complete. Environment: {settings.ENVIRONMENT}")


@app.on_event("shutdown")
async def on_shutdown():
    global scheduler
    if scheduler:
        scheduler.shutdown(wait=False)
        logger.info("eGauge poller scheduler stopped")
    logger.info("Application shutdown complete")


@app.get("/")
async def root():
    return {
        "message": "ESG Dashboard API is running",
        "version": "1.0.0",
        "environment": settings.ENVIRONMENT,
        "docs": "/docs" if settings.DEBUG else None,
        "endpoints": {
            "meters": "/api/meters",
            "assets": "/api/assets",
            "health": "/health",
        },
    }


@app.get("/health")
async def health_check():
    from app.services.egauge_poller import STATUS

    egauge_health = "unknown"
    if STATUS.get("bertha-house"):
        egauge_health = STATUS["bertha-house"].get("health", "unknown")

    db_status = "unknown"
    try:
        from app.core.database import db
        await db.command("ping")
        db_status = "healthy"
    except Exception as e:
        db_status = f"error: {str(e)}"
        logger.error(f"Database health check failed: {e}")

    return {
        "status": "healthy",
        "version": "1.0.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "services": {
            "database": db_status,
            "egauge": egauge_health,
            "scheduler": "running" if scheduler else "stopped",
        },
        "environment": settings.ENVIRONMENT,
    }
