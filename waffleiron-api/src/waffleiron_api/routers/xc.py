"""XC integration endpoints — connectivity, namespaces, and push-to-XC."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request

from waffleiron.xc_client.client import XCClient
from waffleiron.xc_client.config import XCConfig
from waffleiron_api.sessions import SessionStore

router = APIRouter(tags=["xc"])

# Maps the push request object type → (XC API resource path, TranslationResult attribute)
_OBJECT_TYPE_MAP: dict[str, tuple[str, str]] = {
    "app_firewall": ("app_firewalls", "app_firewall"),
    "waf_exclusion_policy": ("waf_exclusion_policys", "exclusion_policy"),
    "exclusion_policy": ("waf_exclusion_policys", "exclusion_policy"),
    "service_policy": ("service_policys", "service_policy"),
}

# http_lb_patch is a reference snippet, not a standalone XC object — it cannot be pushed directly
_NON_PUSHABLE = {"http_lb_patch"}


# ── Dependency helpers ──────────────────────────────────────────────


def _get_store(request: Request) -> SessionStore:
    return request.app.state.session_store


def _get_session(request: Request, conversion_id: str):
    store = _get_store(request)
    session = store.get(conversion_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Conversion session not found")
    return session


def _resolve_xc_client(request: Request, tenant_url: str | None = None, api_token: str | None = None) -> XCClient:
    """Build an XCClient from explicit credentials or fall back to app-level config."""
    if tenant_url and api_token:
        config = XCConfig(tenant_url=tenant_url, api_token=api_token, auth_method="token")
        return XCClient(config)

    app_config = request.app.state.config.xc_config
    if app_config is not None:
        return XCClient(app_config)

    raise HTTPException(status_code=400, detail="No XC credentials provided or configured")


# ── GET /xc/status ─────────────────────────────────────────────────


@router.get("/xc/status")
async def xc_status(request: Request):
    """Return whether XC credentials are configured at the app level."""
    xc_config = request.app.state.config.xc_config
    configured = xc_config is not None
    return {
        "configured": configured,
        "tenant_url": xc_config.tenant_url if configured else None,
    }


# ── POST /xc/connect ──────────────────────────────────────────────


@router.post("/xc/connect")
async def xc_connect(request: Request):
    """Test connectivity to an XC tenant using provided credentials."""
    body = await request.json()
    xc_client = _resolve_xc_client(
        request,
        tenant_url=body.get("tenant_url"),
        api_token=body.get("api_token"),
    )
    connected = xc_client.check_connection()
    return {"connected": connected}


# ── GET /xc/namespaces ────────────────────────────────────────────


@router.get("/xc/namespaces")
async def xc_namespaces(request: Request, tenant_url: str | None = None, api_token: str | None = None):
    """List namespaces from the XC API, always prepending 'shared'."""
    xc_client = _resolve_xc_client(request, tenant_url, api_token)
    items = xc_client.list_namespaces()
    names = [item["name"] for item in items]
    # Always include "shared" at the front
    if "shared" not in names:
        names.insert(0, "shared")
    else:
        names.remove("shared")
        names.insert(0, "shared")
    return {"namespaces": names}


# ── POST /conversions/{id}/push ───────────────────────────────────


@router.post("/conversions/{conversion_id}/push")
async def push_to_xc(request: Request, conversion_id: str):
    """Push translated XC objects to an F5 XC tenant."""
    session = _get_session(request, conversion_id)

    if session.translation is None:
        raise HTTPException(status_code=400, detail="Translation not yet performed")

    body = await request.json()
    object_types = body["objects"]

    xc_client = _resolve_xc_client(
        request,
        tenant_url=body.get("tenant_url"),
        api_token=body.get("api_token"),
    )

    results = []
    for obj_type in object_types:
        if obj_type in _NON_PUSHABLE:
            results.append(
                {"object_type": obj_type, "success": True, "message": "reference only, not pushed"}
            )
            continue

        mapping = _OBJECT_TYPE_MAP.get(obj_type)
        if mapping is None:
            results.append(
                {"object_type": obj_type, "success": False, "error": "not available"}
            )
            continue

        resource, attr_name = mapping
        obj_data = getattr(session.translation, attr_name, None)
        if obj_data is None:
            results.append(
                {"object_type": obj_type, "success": False, "error": "not available"}
            )
            continue

        # Read namespace from the object's own metadata
        obj_namespace = obj_data.get("metadata", {}).get("namespace", "default")

        try:
            xc_client.create_object(resource, obj_namespace, obj_data)
            results.append({"object_type": obj_type, "success": True, "namespace": obj_namespace})
        except Exception as e:
            results.append(
                {"object_type": obj_type, "success": False, "error": str(e), "namespace": obj_namespace}
            )

    return {"results": results}


# ── POST /conversions/{id}/push/delete ────────────────────────────


@router.post("/conversions/{conversion_id}/push/delete")
async def delete_from_xc(request: Request, conversion_id: str):
    """Delete previously pushed XC objects from the tenant."""
    session = _get_session(request, conversion_id)

    if session.translation is None:
        raise HTTPException(status_code=400, detail="Translation not yet performed")

    body = await request.json()
    object_types = body["objects"]

    xc_client = _resolve_xc_client(
        request,
        tenant_url=body.get("tenant_url"),
        api_token=body.get("api_token"),
    )

    results = []
    for obj_type in object_types:
        if obj_type in _NON_PUSHABLE:
            results.append({"object_type": obj_type, "success": True, "message": "reference only, nothing to delete"})
            continue

        mapping = _OBJECT_TYPE_MAP.get(obj_type)
        if mapping is None:
            results.append({"object_type": obj_type, "success": False, "error": "unknown type"})
            continue

        resource, attr_name = mapping
        obj_data = getattr(session.translation, attr_name, None)
        if obj_data is None:
            results.append({"object_type": obj_type, "success": False, "error": "not available"})
            continue

        obj_namespace = obj_data.get("metadata", {}).get("namespace", "default")
        obj_name = obj_data.get("metadata", {}).get("name", "")

        try:
            xc_client.delete_object(resource, obj_namespace, obj_name)
            results.append({"object_type": obj_type, "success": True, "namespace": obj_namespace})
        except Exception as e:
            results.append({"object_type": obj_type, "success": False, "error": str(e), "namespace": obj_namespace})

    return {"results": results}
