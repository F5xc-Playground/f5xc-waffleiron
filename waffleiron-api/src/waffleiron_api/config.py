"""API configuration resolved from environment variables."""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass

from waffleiron.xc_client.config import XCConfig

logger = logging.getLogger(__name__)


@dataclass
class ApiConfig:
    """Application-level configuration for the WaffleIron API."""

    session_ttl: int = 3600
    log_level: str = "info"
    port: int = 8000
    xc_config: XCConfig | None = None

    @classmethod
    def from_env(cls) -> ApiConfig:
        """Build config from environment variables.

        Reads:
            SESSION_TTL  – session time-to-live in seconds (default 3600)
            LOG_LEVEL    – Python log level name (default "info")
            PORT         – HTTP listen port (default 8000)
            F5XC_*       – XC connection vars (optional, via XCConfig.from_env)
        """
        session_ttl = int(os.environ.get("SESSION_TTL", "3600"))
        log_level = os.environ.get("LOG_LEVEL", "info")
        port = int(os.environ.get("PORT", "8000"))

        xc_config: XCConfig | None = None
        try:
            xc_config = XCConfig.from_env()
        except (ValueError, FileNotFoundError) as exc:
            logger.warning("XC configuration not available: %s", exc)

        return cls(
            session_ttl=session_ttl,
            log_level=log_level,
            port=port,
            xc_config=xc_config,
        )
