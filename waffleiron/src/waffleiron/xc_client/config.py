"""XC client configuration — credential resolution from env vars and K8s secrets."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Optional

_DEFAULT_P12_PATH = "/certs/api-creds.p12"
_DEFAULT_TOKEN_FILE = "/secrets/api-token"


@dataclass
class XCConfig:
    """Resolved F5 XC API credentials and endpoint configuration."""

    tenant_url: str
    auth_method: Literal["token", "p12"]
    api_token: Optional[str] = None
    p12_path: Optional[str] = None
    p12_password: Optional[str] = None

    @classmethod
    def from_env(cls) -> Optional["XCConfig"]:
        """Resolve configuration from environment variables.

        Credential resolution order:
        - Token auth: F5XC_API_TOKEN_FILE (takes precedence) or F5XC_API_TOKEN env var;
          also checks /secrets/api-token as a default K8s secret path.
        - P12 auth: F5XC_P12_PATH (or default /certs/api-creds.p12) + F5XC_P12_PASSWORD.

        Returns None if no credentials are found.
        Raises ValueError if both token and P12 credentials are present.
        """
        tenant_url = os.environ.get("F5XC_TENANT_URL")

        # --- resolve token ---
        token: Optional[str] = None
        token_file_path = os.environ.get("F5XC_API_TOKEN_FILE")
        if token_file_path:
            p = Path(token_file_path)
            if p.exists():
                token = p.read_text().strip()
        elif Path(_DEFAULT_TOKEN_FILE).exists():
            token = Path(_DEFAULT_TOKEN_FILE).read_text().strip()

        if token is None:
            token = os.environ.get("F5XC_API_TOKEN")

        # --- resolve p12 ---
        p12_path_str: Optional[str] = None
        p12_password = os.environ.get("F5XC_P12_PASSWORD")
        explicit_p12 = os.environ.get("F5XC_P12_PATH")
        if explicit_p12:
            if Path(explicit_p12).exists():
                p12_path_str = explicit_p12
        elif p12_password and Path(_DEFAULT_P12_PATH).exists():
            p12_path_str = _DEFAULT_P12_PATH

        has_token = bool(token)
        has_p12 = bool(p12_path_str and p12_password)

        if not has_token and not has_p12:
            return None

        if has_token and has_p12:
            raise ValueError(
                "Mutually exclusive credentials: both token and P12 auth are configured. "
                "Set only one of F5XC_API_TOKEN/F5XC_API_TOKEN_FILE or F5XC_P12_PATH."
            )

        if not tenant_url:
            return None

        if has_token:
            return cls(
                tenant_url=tenant_url,
                auth_method="token",
                api_token=token,
            )

        return cls(
            tenant_url=tenant_url,
            auth_method="p12",
            p12_path=p12_path_str,
            p12_password=p12_password,
        )
