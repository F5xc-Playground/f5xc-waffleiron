"""Manifest generation for WaffleIron output bundles."""

from __future__ import annotations

from datetime import datetime, timezone

from waffleiron.translators import TranslationResult
from waffleiron.translators.utils import XC_RESOURCE_TYPES


def build_manifest(
    result: TranslationResult,
    namespace: str,
    source_policy: str,
) -> dict:
    """Build a manifest dict compatible with f5xc-namespace-backup."""
    resource_counts: dict[str, int] = {}
    for attr_name, kind_info in XC_RESOURCE_TYPES.items():
        obj = getattr(result, attr_name, None)
        if obj is not None:
            resource_counts[kind_info["kind"]] = 1

    advisory: list[str] = []
    if result.http_lb_patch is not None:
        advisory.append("http_lb_patch")

    return {
        "version": "1",
        "tool": "waffleiron",
        "tool_version": _get_version(),
        "source_policy": source_policy,
        "namespace": namespace,
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "resource_counts": resource_counts,
        "advisory": advisory if advisory else None,
        "warnings": None,
        "errors": None,
    }


def _get_version() -> str:
    try:
        from waffleiron import __version__
        return __version__
    except ImportError:
        return "0.0.0"
