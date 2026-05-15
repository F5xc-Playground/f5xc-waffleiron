"""FastAPI application entry point for WaffleIron API."""

from fastapi import FastAPI

from waffleiron_api.config import ApiConfig
from waffleiron_api.routers import conversions, xc
from waffleiron_api.sessions import SessionStore

config = ApiConfig.from_env()
session_store = SessionStore(ttl_seconds=config.session_ttl)

app = FastAPI(title="WaffleIron API", version="0.1.0")
app.state.session_store = session_store
app.state.config = config

app.include_router(conversions.router, prefix="/api/v1")
app.include_router(xc.router, prefix="/api/v1")


@app.get("/healthz")
async def healthz():
    return {"status": "ok", "xc_configured": config.xc_config is not None}
