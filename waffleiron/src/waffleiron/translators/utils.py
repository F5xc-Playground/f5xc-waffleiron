"""Shared utilities for AWAF-to-XC translators."""

from __future__ import annotations

import re


def sanitize_xc_name(name: str) -> str:
    """Sanitize a name for XC: lowercase, alphanumeric + hyphens, max 64 chars."""
    lowered = name.lower()
    sanitized = re.sub(r"[^a-z0-9-]+", "-", lowered)
    sanitized = re.sub(r"-{2,}", "-", sanitized)
    sanitized = sanitized.strip("-")[:64].strip("-")
    if not sanitized:
        raise ValueError(f"Name {name!r} produces an empty XC resource name after sanitization")
    return sanitized


def path_slug(path: str) -> str:
    """Convert a URL path to a kebab-case slug suitable for rule names."""
    slug = re.sub(r"[^a-z0-9]+", "-", path.lower())
    slug = slug.strip("-")
    return slug or "root"


XC_RESOURCE_TYPES: dict[str, dict[str, str]] = {
    "app_firewall": {
        "kind": "app-firewall",
        "list_path": "/api/config/namespaces/{namespace}/app_firewalls",
        "suffix": "-waf",
    },
    "exclusion_policy": {
        "kind": "waf-exclusion-policy",
        "list_path": "/api/config/namespaces/{namespace}/waf_exclusion_policys",
        "suffix": "-exc",
    },
    "service_policy": {
        "kind": "service-policy",
        "list_path": "/api/config/namespaces/{namespace}/service_policys",
        "suffix": "-svc",
    },
}


def build_metadata(
    name: str,
    namespace: str,
    source_policy: str,
    resource_type: str,
) -> dict:
    kind_info = XC_RESOURCE_TYPES.get(resource_type, {})
    kind = kind_info.get("kind", resource_type)
    return {
        "annotations": {},
        "description": f"Converted from AWAF policy '{source_policy}' by WaffleIron ({kind})",
        "disable": False,
        "labels": {"ves.io/app_type": "waffleiron"},
        "name": name,
        "namespace": namespace,
    }
