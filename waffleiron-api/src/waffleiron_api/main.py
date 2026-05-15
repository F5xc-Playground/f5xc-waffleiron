"""FastAPI application entry point for WaffleIron API."""

import os
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from waffleiron_api.config import ApiConfig
from waffleiron_api.routers import conversions, xc
from waffleiron_api.sessions import SessionStore

config = ApiConfig.from_env()
session_store = SessionStore(ttl_seconds=config.session_ttl)

app = FastAPI(title="WaffleIron API", version="0.1.0")
app.state.session_store = session_store
app.state.config = config

# --- API routes (must be registered before the SPA catch-all) ---
app.include_router(conversions.router, prefix="/api/v1")
app.include_router(xc.router, prefix="/api/v1")


@app.get("/healthz")
async def healthz():
    return {"status": "ok", "xc_configured": config.xc_config is not None}


# --- Static file serving (SPA) ---
STATIC_DIR = Path(os.getenv("STATIC_DIR", "static"))

if STATIC_DIR.exists():
    app.mount("/assets", StaticFiles(directory=STATIC_DIR / "assets"), name="assets")

    # SPA fallback: serve index.html for non-API, non-asset routes
    @app.get("/{path:path}")
    async def spa_fallback(path: str):
        return FileResponse(STATIC_DIR / "index.html")
