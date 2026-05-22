"""AWAF policy format parsers — XML and JSON."""

from pathlib import Path

from waffleiron.model import AsmPolicy
from waffleiron.parsers.detect import PolicyFormat, detect_format
from waffleiron.parsers.json_parser import JsonPolicyParser
from waffleiron.parsers.xml_parser import XmlPolicyParser


def parse(path: Path | str) -> AsmPolicy:
    """Auto-detect the policy format and parse accordingly."""
    content = Path(path).read_bytes()
    fmt = detect_format(content)
    if fmt == PolicyFormat.XML:
        return XmlPolicyParser.parse(path)
    return JsonPolicyParser.parse(path)


__all__ = ["PolicyFormat", "detect_format", "parse", "JsonPolicyParser", "XmlPolicyParser"]
