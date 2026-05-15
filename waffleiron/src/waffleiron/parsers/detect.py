"""Auto-detect whether raw policy bytes are ASM XML or Declarative JSON."""

import enum


class PolicyFormat(enum.Enum):
    """Supported ASM policy export formats."""

    XML = "xml"
    JSON = "json"


def detect_format(content: bytes) -> PolicyFormat:
    """Return the detected policy format for *content*.

    Raises ``ValueError`` for empty or unrecognized input.
    """
    if not content:
        raise ValueError("Empty input")
    stripped = content.lstrip()
    if stripped.startswith(b"<?xml") or stripped.startswith(b"<"):
        return PolicyFormat.XML
    if stripped.startswith(b"{"):
        return PolicyFormat.JSON
    raise ValueError(
        "Unrecognized policy format: expected XML (starts with '<') or JSON (starts with '{')"
    )
