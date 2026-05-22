"""Tests for backup-tool-compatible output format."""

import json

from waffleiron.translators import TranslationResult
from waffleiron.translators.utils import build_metadata


def _make_obj(name: str, namespace: str, resource_type: str, spec: dict) -> dict:
    return {
        "metadata": build_metadata(
            name=name, namespace=namespace, source_policy="test", resource_type=resource_type,
        ),
        "spec": spec,
    }


class TestOutputFiles:
    def test_returns_kind_name_paths(self):
        result = TranslationResult(
            app_firewall=_make_obj("my-waf", "ns", "app_firewall", {"blocking": {}}),
            exclusion_policy=_make_obj("my-exc", "ns", "exclusion_policy", {"waf_exclusion_rules": []}),
            service_policy=None,
            http_lb_patch={"csrf": {"enabled": True, "urls": []}},
        )
        files = result.output_files()

        assert "app-firewall/my-waf.json" in files
        assert "waf-exclusion-policy/my-exc.json" in files
        assert "_advisory/http_lb_patch.json" in files
        assert not any("service-policy" in k for k in files)

    def test_excludes_none_objects(self):
        result = TranslationResult(
            app_firewall=_make_obj("fw", "ns", "app_firewall", {}),
            exclusion_policy=None,
            service_policy=None,
            http_lb_patch=None,
        )
        files = result.output_files()
        assert len(files) == 1
        assert "app-firewall/fw.json" in files

    def test_objects_have_metadata_and_spec(self):
        result = TranslationResult(
            app_firewall=_make_obj("fw", "ns", "app_firewall", {"blocking": {}}),
            exclusion_policy=None,
            service_policy=None,
            http_lb_patch=None,
        )
        for path, obj in result.output_files().items():
            if not path.startswith("_advisory/"):
                assert set(obj.keys()) == {"metadata", "spec"}

    def test_all_three_objects(self):
        result = TranslationResult(
            app_firewall=_make_obj("p-waf", "ns", "app_firewall", {}),
            exclusion_policy=_make_obj("p-exc", "ns", "exclusion_policy", {}),
            service_policy=_make_obj("p-svc", "ns", "service_policy", {}),
            http_lb_patch=None,
        )
        files = result.output_files()
        assert len(files) == 3
        assert "app-firewall/p-waf.json" in files
        assert "waf-exclusion-policy/p-exc.json" in files
        assert "service-policy/p-svc.json" in files

    def test_json_serializable(self):
        result = TranslationResult(
            app_firewall=_make_obj("fw", "ns", "app_firewall", {"blocking": {}}),
            exclusion_policy=None,
            service_policy=None,
            http_lb_patch=None,
        )
        for path, obj in result.output_files().items():
            serialized = json.dumps(obj, indent=2)
            assert json.loads(serialized) == obj
