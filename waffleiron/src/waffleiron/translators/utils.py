"""Shared utilities for ASM-to-XC translators."""

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
