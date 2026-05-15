"""XC integration endpoints — connectivity, namespaces, and push-to-XC."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request

from waffleiron.xc_client.client import XCClient
from waffleiron.xc_client.config import XCConfig

router = APIRouter(tags=["xc"])

# Maps the push request object type → (XC API resource path, TranslationResult attribute)
_OBJECT_TYPE_MAP: dict[str, tuple[str, str]] = {
    "app_firewall": ("app_firewalls", "app_firewall"),
    "waf_exclusion_policy": ("waf_exclusion_policys", "exclusion_policy"),
    "exclusion_policy": ("waf_exclusion_policys", "exclusion_policy"),
    "service_policy": ("service_policys", "service_policy"),
    "http_lb_patch": ("http_loadbalancers", "http_lb_patch"),
}


# ── Dependency helpers ──────────────────────────────────────────────


def _get_store(request: Request) -> SessionStore:
    return request.app.state.session_store


def _get_session(request: Request, conversion_id: str):
    store = _get_store(request)
    session = store.get(conversion_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Conversion session not found")
    return session


def _make_xc_client(tenant_url: str, api_token: str) -> XCClient:
    """Construct an XCClient from ad-hoc credentials."""
    config = XCConfig(tenant_url=tenant_url, api_token=api_token, auth_method="token")
    return XCClient(config)


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
    tenant_url = body["tenant_url"]
    api_token = body["api_token"]

    xc_client = _make_xc_client(tenant_url, api_token)
    connected = xc_client.check_connection()
    return {"connected": connected}


# ── GET /xc/namespaces ────────────────────────────────────────────


@router.get("/xc/namespaces")
async def xc_namespaces(tenant_url: str, api_token: str):
    """List namespaces from the XC API, always prepending 'shared'."""
    xc_client = _make_xc_client(tenant_url, api_token)
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
    namespace = body["namespace"]
    tenant_url = body["tenant_url"]
    api_token = body["api_token"]
    object_types = body["objects"]

    xc_client = _make_xc_client(tenant_url, api_token)

    results = []
    for obj_type in object_types:
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

        try:
            xc_client.create_object(resource, namespace, obj_data)
            results.append({"object_type": obj_type, "success": True})
        except Exception as e:
            results.append(
                {"object_type": obj_type, "success": False, "error": str(e)}
            )

    return {"results": results}
