"""Conversion workflow endpoints."""

from __future__ import annotations

import dataclasses
import json
import tempfile
from pathlib import Path

from fastapi import APIRouter, HTTPException, Request, Response, UploadFile
from fastapi.responses import JSONResponse

from waffleiron import (
    DecisionSet,
    ReportFormat,
    analyze,
    generate_report,
    parse,
    translate,
)
from waffleiron.decisions import AlarmOnlyAction, SignatureDecision

from waffleiron_api.sessions import SessionStore

router = APIRouter(tags=["conversions"])


# ── Dependency helpers ──────────────────────────────────────────────


def _get_store(request: Request) -> SessionStore:
    return request.app.state.session_store


def _get_session(request: Request, conversion_id: str):
    store = _get_store(request)
    session = store.get(conversion_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Conversion session not found")
    return session


# ── POST /conversions — upload and parse ────────────────────────────


@router.post("/conversions", status_code=201)
async def create_conversion(request: Request, file: UploadFile):
    """Upload an ASM policy file (XML or JSON), parse it, and create a session."""
    store = _get_store(request)

    content = await file.read()
    suffix = Path(file.filename).suffix if file.filename else ".xml"

    with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as tmp:
        tmp.write(content)
        tmp_path = Path(tmp.name)

    try:
        policy = parse(tmp_path)
    except Exception as e:
        raise HTTPException(status_code=422, detail=str(e))
    finally:
        tmp_path.unlink(missing_ok=True)

    session_id = store.create()
    session = store.get(session_id)
    session.asm_policy = policy
    session.policy_name = policy.name
    session.status = "parsed"

    return {"id": session_id, "status": session.status, "policy_name": session.policy_name}


# ── GET /conversions/{id} — session status ──────────────────────────


@router.get("/conversions/{conversion_id}")
async def get_conversion(request: Request, conversion_id: str):
    """Return the current status and metadata for a conversion session."""
    session = _get_session(request, conversion_id)
    return {
        "id": session.id,
        "status": session.status,
        "policy_name": session.policy_name,
    }


# ── GET /conversions/{id}/analysis — lazy analysis ─────────────────


@router.get("/conversions/{conversion_id}/analysis")
async def get_analysis(request: Request, conversion_id: str):
    """Analyze the parsed ASM policy. Runs analysis lazily on first access."""
    session = _get_session(request, conversion_id)

    if session.asm_policy is None:
        raise HTTPException(status_code=400, detail="No policy parsed yet")

    if session.analysis is None:
        session.analysis = analyze(session.asm_policy)
        session.status = "analyzed"

    result = session.analysis
    policy = session.asm_policy

    policy_info = {
        "name": policy.name,
        "enforcement_mode": policy.enforcement_mode.value,
        "encoding": policy.encoding,
        "signature_accuracy": policy.signatures.accuracy_level.value,
        "staging_enabled": policy.signatures.staging_enabled,
        "threat_campaigns_enabled": policy.signatures.threat_campaigns_enabled,
        "features": {
            "data_guard": policy.data_guard.enabled,
            "csrf": policy.csrf.enabled,
            "bot_defense": policy.bot_defense.enabled,
            "brute_force": policy.brute_force.enabled,
            "session_tracking": policy.session_tracking.enabled,
            "ip_intelligence": len(policy.ip_intelligence.categories) > 0,
            "geolocation": len(policy.geolocation.disallowed) > 0,
            "blocking_page": policy.blocking_page.enabled,
        },
        "entity_counts": {
            "urls": len(policy.entities.urls),
            "parameters": len(policy.entities.parameters),
            "file_types": len(policy.entities.file_types),
            "cookies": len(policy.entities.cookies),
            "headers": len(policy.entities.headers),
            "signature_overrides": len(policy.signatures.global_overrides),
            "violations": len(policy.violations),
            "whitelist_ips": len(policy.whitelist_ips),
        },
    }

    return {
        "policy_info": policy_info,
        "summary": dataclasses.asdict(result.summary),
        "alarm_only_signatures": [dataclasses.asdict(s) for s in result.alarm_only_signatures],
        "alarm_only_violations": [dataclasses.asdict(v) for v in result.alarm_only_violations],
        "untranslatable": dataclasses.asdict(result.untranslatable),
        "bot_gaps": [dataclasses.asdict(g) for g in result.bot_gaps],
        "warnings": [dataclasses.asdict(w) for w in result.warnings],
    }


# ── PUT /conversions/{id}/decisions — submit decisions ──────────────


@router.put("/conversions/{conversion_id}/decisions")
async def submit_decisions(request: Request, conversion_id: str):
    """Submit user enforcement decisions for alarm-only signatures/violations."""
    session = _get_session(request, conversion_id)
    body = await request.json()

    ds = DecisionSet()
    action_map = {
        "exclude": AlarmOnlyAction.EXCLUDE,
        "enforce": AlarmOnlyAction.ENFORCE,
        "defer": AlarmOnlyAction.DEFER,
    }

    for sig in body.get("alarm_only_signatures", []):
        action_str = sig.get("action", "defer")
        ds.add_signature(
            SignatureDecision(
                sig_id=sig["sig_id"],
                description=sig.get("description", ""),
                scope=sig.get("scope", "global"),
                action=action_map.get(action_str, AlarmOnlyAction.DEFER),
            )
        )

    session.decisions = ds
    session.status = "decisions_submitted"

    return {"id": session.id, "status": session.status}


# ── POST /conversions/{id}/translate — run translation ──────────────


@router.post("/conversions/{conversion_id}/translate")
async def translate_conversion(request: Request, conversion_id: str):
    """Translate the parsed ASM policy using submitted decisions."""
    session = _get_session(request, conversion_id)
    body = await request.json()
    namespace = body.get("namespace", "default")
    name_override = body.get("name")

    if session.asm_policy is None:
        raise HTTPException(status_code=400, detail="No policy parsed yet")

    result = translate(session.asm_policy, session.decisions, namespace, name_override)
    session.translation = result
    session.status = "translated"

    # Build outputs dict — only include non-None results
    outputs = {}
    for attr in ("app_firewall", "exclusion_policy", "service_policy", "http_lb_patch"):
        value = getattr(result, attr, None)
        if value is not None:
            outputs[attr] = value

    return {"id": session.id, "status": session.status, "outputs": outputs}


# ── GET /conversions/{id}/outputs — list available outputs ──────────


@router.get("/conversions/{conversion_id}/outputs")
async def list_outputs(request: Request, conversion_id: str):
    """List the available output object types for a translated session."""
    session = _get_session(request, conversion_id)

    if session.translation is None:
        raise HTTPException(status_code=400, detail="Translation not yet performed")

    available = []
    for attr in ("app_firewall", "exclusion_policy", "service_policy", "http_lb_patch"):
        if getattr(session.translation, attr, None) is not None:
            available.append(attr)

    return {"available": available}


# ── GET /conversions/{id}/outputs/{object_type} — download output ───


@router.get("/conversions/{conversion_id}/outputs/{object_type}")
async def get_output(request: Request, conversion_id: str, object_type: str):
    """Download a specific translated output object as JSON."""
    session = _get_session(request, conversion_id)

    if session.translation is None:
        raise HTTPException(status_code=400, detail="Translation not yet performed")

    value = getattr(session.translation, object_type, None)
    if value is None:
        raise HTTPException(status_code=404, detail=f"Output '{object_type}' not available")

    return value


# ── GET /conversions/{id}/report — generate report ─────────────────


@router.get("/conversions/{conversion_id}/report")
async def get_report(request: Request, conversion_id: str):
    """Generate a conversion gap report in JSON or Markdown format."""
    session = _get_session(request, conversion_id)

    if session.asm_policy is None:
        raise HTTPException(status_code=400, detail="No policy parsed yet")

    # Ensure analysis has been run
    if session.analysis is None:
        session.analysis = analyze(session.asm_policy)

    accept = request.headers.get("accept", "application/json")

    if "text/markdown" in accept:
        fmt = ReportFormat.MARKDOWN
    else:
        fmt = ReportFormat.JSON

    enforcement_mode = getattr(session.asm_policy, "enforcement_mode", "")
    if hasattr(enforcement_mode, "value"):
        enforcement_mode = enforcement_mode.value

    report_str = generate_report(
        session.analysis,
        session.decisions,
        fmt,
        policy_name=session.policy_name or "",
        enforcement_mode=enforcement_mode,
    )

    if fmt == ReportFormat.MARKDOWN:
        return Response(content=report_str, media_type="text/markdown")
    else:
        return JSONResponse(content=json.loads(report_str))


# ── DELETE /conversions/{id} — cleanup session ─────────────────────


@router.delete("/conversions/{conversion_id}", status_code=204)
async def delete_conversion(request: Request, conversion_id: str):
    """Delete a conversion session and free resources."""
    session = _get_store(request).get(conversion_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Conversion session not found")
    _get_store(request).delete(conversion_id)
    return Response(status_code=204)
