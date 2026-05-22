"""Tests for manifest generation."""

import json

from waffleiron.manifest import build_manifest
from waffleiron.translators import TranslationResult
from waffleiron.translators.utils import build_metadata


def _make_obj(name: str, namespace: str, resource_type: str, spec: dict) -> dict:
    return {
        "metadata": build_metadata(
            name=name, namespace=namespace, source_policy="test", resource_type=resource_type,
        ),
        "spec": spec,
    }


class TestBuildManifest:
    def _make_result(self) -> TranslationResult:
        return TranslationResult(
            app_firewall=_make_obj("p-waf", "ns", "app_firewall", {"blocking": {}}),
            exclusion_policy=_make_obj("p-exc", "ns", "exclusion_policy", {"waf_exclusion_rules": []}),
            service_policy=None,
            http_lb_patch=None,
        )

    def test_has_required_fields(self):
        m = build_manifest(result=self._make_result(), namespace="my-ns", source_policy="my-asm-policy")
        assert m["version"] == "1"
        assert m["tool"] == "waffleiron"
        assert "tool_version" in m
        assert m["namespace"] == "my-ns"
        assert m["source_policy"] == "my-asm-policy"
        assert "timestamp" in m

    def test_resource_counts(self):
        m = build_manifest(result=self._make_result(), namespace="ns", source_policy="p")
        assert m["resource_counts"] == {"app-firewall": 1, "waf-exclusion-policy": 1}

    def test_no_counts_for_none_objects(self):
        result = TranslationResult(
            app_firewall=_make_obj("fw", "ns", "app_firewall", {}),
            exclusion_policy=None,
            service_policy=None,
            http_lb_patch=None,
        )
        m = build_manifest(result=result, namespace="ns", source_policy="p")
        assert "waf-exclusion-policy" not in m["resource_counts"]
        assert "service-policy" not in m["resource_counts"]

    def test_advisory_noted(self):
        result = TranslationResult(
            app_firewall=_make_obj("fw", "ns", "app_firewall", {}),
            exclusion_policy=None,
            service_policy=None,
            http_lb_patch={"csrf": {"enabled": True}},
        )
        m = build_manifest(result=result, namespace="ns", source_policy="p")
        assert "http_lb_patch" in m["advisory"]

    def test_advisory_none_when_empty(self):
        m = build_manifest(result=self._make_result(), namespace="ns", source_policy="p")
        assert m["advisory"] is None

    def test_serializable(self):
        m = build_manifest(result=self._make_result(), namespace="ns", source_policy="p")
        serialized = json.dumps(m, indent=2)
        assert json.loads(serialized) == m
