"""Pydantic models for API request/response bodies."""

from __future__ import annotations

from pydantic import BaseModel


# ── Conversion lifecycle responses ──────────────────────────────────


class ConversionResponse(BaseModel):
    """Returned after uploading / parsing an ASM policy."""

    id: str
    status: str
    policy_name: str | None = None


class AnalysisResponse(BaseModel):
    """Returned after analyzing a parsed ASM policy."""

    id: str
    status: str
    summary: dict
    alarm_only_signatures: list[dict]
    alarm_only_violations: list[dict]


# ── Decision submission ─────────────────────────────────────────────


class DecisionRequest(BaseModel):
    """User-submitted enforcement decisions."""

    signatures: list[dict] = []
    violations: list[dict] = []
    bots: list[dict] = []


# ── Translation ─────────────────────────────────────────────────────


class TranslationResponse(BaseModel):
    """Returned after translating decisions into XC objects."""

    id: str
    status: str
    objects: dict


# ── Push to F5 XC ──────────────────────────────────────────────────


class PushRequest(BaseModel):
    """Parameters for pushing translated objects to F5 XC."""

    namespace: str
    create_if_missing: bool = False


class PushResponse(BaseModel):
    """Returned after a push operation."""

    id: str
    status: str
    results: dict


# ── XC connectivity ─────────────────────────────────────────────────


class XCStatusResponse(BaseModel):
    """Health/status of the F5 XC connection."""

    connected: bool
    tenant_url: str | None = None
    namespaces: list[str] = []
