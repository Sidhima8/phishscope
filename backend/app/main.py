import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.core.config import settings
from app.db.init_db import init_db
from app.api.v1 import auth, cases, ingest, notes, reports, indicators, dashboard, integrations

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("phishscope")


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Initializing PhishScope platform...")
    await init_db()
    logger.info("PhishScope initialization complete. Ready for analysis requests.")
    yield
    logger.info("PhishScope platform shutting down.")


app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="Dynamic Phishing Investigation and Threat Intelligence Platform for SOC Analysts",
    lifespan=lifespan
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allows browser frontend during development and container deployment
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register API v1 Routers
app.include_router(auth.router, prefix=f"{settings.API_V1_STR}/auth", tags=["Authentication"])
app.include_router(cases.router, prefix=f"{settings.API_V1_STR}/cases", tags=["Investigation Cases"])
app.include_router(ingest.router, prefix=f"{settings.API_V1_STR}/ingest", tags=["Email Ingestion"])
app.include_router(notes.router, prefix=f"{settings.API_V1_STR}/notes", tags=["Analyst Notes"])
app.include_router(reports.router, prefix=f"{settings.API_V1_STR}/reports", tags=["Forensic Reports"])
app.include_router(indicators.router, prefix=f"{settings.API_V1_STR}/indicators", tags=["Threat Indicators"])
app.include_router(dashboard.router, prefix=f"{settings.API_V1_STR}/dashboard", tags=["Analyst Dashboard"])
app.include_router(integrations.router, prefix=f"{settings.API_V1_STR}/integrations", tags=["Threat Integrations"])


@app.get("/api/health", tags=["Health"])
async def health_check():
    return {
        "status": "OPERATIONAL",
        "platform": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "engine": "PhishScope Heuristic & Threat Intelligence Engine"
    }


# Mount built frontend static files for seamless full-stack deployment
import os
from fastapi.staticfiles import StaticFiles

frontend_dist = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "frontend", "dist"))
if os.path.exists(frontend_dist):
    app.mount("/", StaticFiles(directory=frontend_dist, html=True), name="frontend")
else:
    @app.get("/", tags=["Root"])
    async def root():
        return {
            "name": settings.PROJECT_NAME,
            "version": settings.VERSION,
            "docs_url": "/docs",
            "api_v1": settings.API_V1_STR,
            "frontend_status": "Run 'npm run dev' in frontend directory or run 'npm run build' to bundle"
        }

