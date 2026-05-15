"""Tests for format auto-detection."""

import pytest

from waffleiron.parsers.detect import PolicyFormat, detect_format


def test_detect_xml(fixtures_path):
    content = (fixtures_path / "minimal_blocking.xml").read_bytes()
    assert detect_format(content) == PolicyFormat.XML


def test_detect_json(fixtures_path):
    content = (fixtures_path / "minimal_blocking.json").read_bytes()
    assert detect_format(content) == PolicyFormat.JSON


def test_detect_invalid():
    with pytest.raises(ValueError, match="Unrecognized policy format"):
        detect_format(b"this is not a policy")


def test_detect_empty():
    with pytest.raises(ValueError, match="Empty input"):
        detect_format(b"")
