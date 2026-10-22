"""
AI-Powered Cyber Threat Detection & Security Awareness Platform
Backend Entry Point
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
from dotenv import load_dotenv
import os
import logging

from pathlib import Path

# Load environment variables reliably from backend directory regardless of CWD
_env_path = Path(__file__).resolve().parent / ".env"
load_dotenv(dotenv_path=_env_path)
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# Import database manager
from database.mongodb import db_manager


# ─────────────────────────────────────────────
# Application Lifespan (Startup & Shutdown)
# ─────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting up Threat Detection Backend...")
    await db_manager.connect()
    yield
    logger.info("Shutting down Threat Detection Backend...")
    from services.monitoring_service import monitoring_service
    monitoring_service.stop_monitoring()
    await db_manager.disconnect()


# ─────────────────────────────────────────────
# FastAPI Application Instance
# ─────────────────────────────────────────────
app = FastAPI(
    title="Cyber Threat Detection & Awareness API",
    description="""
    AI-Powered Cyber Threat Detection & Security Awareness Platform.
    
    Modules:
    - Email Threat Analyzer (Multi-vector inspection & scoring)
    - Threat Artifact Scanner (URLs, Attachments, & Headers)
    - Email Inbox Integration (Gmail / Outlook / Lab Inbox)
    - Threat Investigation Center (Forensic Dossiers & Remediation Playbooks)
    - AI Explanation & Guidance
    - MongoDB Historical Audit Persistence
    """,
    version="2.2.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan
)

# ─────────────────────────────────────────────
# CORS Middleware
# ─────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://localhost:3000",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─────────────────────────────────────────────
# Register Routers
# ─────────────────────────────────────────────
from routes.analysis import router as analysis_router
from routes.scanner import router as scanner_router
from routes.integration import router as integration_router
from routes.auth import router as auth_router
from routes.investigation import router as investigation_router
from routes.correlation import router as correlation_router
from routes.remediation import router as remediation_router
from routes.verification import router as verification_router
from routes.notification import router as notification_router
from routes.monitoring import router as monitoring_router
from routes.training import router as training_router
app.include_router(analysis_router)
app.include_router(scanner_router)
app.include_router(integration_router)
app.include_router(auth_router)
app.include_router(investigation_router)
app.include_router(correlation_router)
app.include_router(remediation_router)
app.include_router(verification_router)
app.include_router(notification_router)
app.include_router(monitoring_router)
app.include_router(training_router)
logger.info("All routers registered successfully.")


# ─────────────────────────────────────────────
# Health Check Endpoint
# ─────────────────────────────────────────────
@app.get("/api/health", tags=["Health"])
async def health_check():
    return {
        "status": "ok",
        "message": "Cyber Threat Detection API is running",
        "version": "2.2.0",
        "environment": os.getenv("APP_ENV", "development"),
        "database_connected": db_manager.is_connected
    }


# ─────────────────────────────────────────────
# Root Endpoint
# ─────────────────────────────────────────────
@app.get("/", tags=["Root"])
async def root():
    return {
        "message": "Welcome to the Cyber Threat Detection API",
        "docs": "Visit /docs for interactive API documentation",
        "health": "Visit /api/health to check server status"
    }