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


class TestBackupToolCompatibility:
    """Verify output matches f5xc-namespace-backup expected format."""

    def _make_full_result(self) -> TranslationResult:
        return TranslationResult(
            app_firewall=_make_obj("test-waf", "my-ns", "app_firewall", {"blocking": {}}),
            exclusion_policy=_make_obj("test-exc", "my-ns", "exclusion_policy", {"waf_exclusion_rules": []}),
            service_policy=_make_obj("test-svc", "my-ns", "service_policy", {"rule_list": {"rules": []}}),
            http_lb_patch={"csrf": {"enabled": True, "urls": ["/login"]}},
        )

    def test_each_object_has_only_metadata_and_spec(self):
        """Backup tool expects exactly {metadata, spec} — no extra keys."""
        result = self._make_full_result()
        for path, obj in result.output_files().items():
            if path.startswith("_advisory/"):
                continue
            assert set(obj.keys()) == {"metadata", "spec"}, f"{path} has unexpected keys: {set(obj.keys())}"

    def test_metadata_has_all_required_fields(self):
        """Backup tool sanitizer preserves these fields; they must exist."""
        required = {"annotations", "description", "disable", "labels", "name", "namespace"}
        result = self._make_full_result()
        for path, obj in result.output_files().items():
            if path.startswith("_advisory/"):
                continue
            assert set(obj["metadata"].keys()) == required, (
                f"{path} metadata has wrong keys: {set(obj['metadata'].keys())}"
            )

    def test_metadata_types(self):
        """Verify types match what XC API returns after sanitization."""
        result = self._make_full_result()
        for path, obj in result.output_files().items():
            if path.startswith("_advisory/"):
                continue
            md = obj["metadata"]
            assert isinstance(md["annotations"], dict)
            assert isinstance(md["description"], str)
            assert isinstance(md["disable"], bool)
            assert isinstance(md["labels"], dict)
            assert isinstance(md["name"], str)
            assert isinstance(md["namespace"], str)

    def test_file_paths_use_kebab_case_kinds(self):
        result = self._make_full_result()
        for path in result.output_files():
            if path.startswith("_advisory/"):
                continue
            kind = path.split("/")[0]
            assert "_" not in kind, f"Path should use kebab-case kind, got: {path}"

    def test_manifest_has_backup_tool_fields(self):
        from waffleiron.manifest import build_manifest
        result = self._make_full_result()
        m = build_manifest(result=result, namespace="my-ns", source_policy="test")
        assert m["version"] == "1"
        assert isinstance(m["resource_counts"], dict)
        assert "app-firewall" in m["resource_counts"]
        assert "waf-exclusion-policy" in m["resource_counts"]
        assert "service-policy" in m["resource_counts"]
        assert "timestamp" in m

    def test_all_objects_json_serializable(self):
        result = self._make_full_result()
        for path, obj in result.output_files().items():
            serialized = json.dumps(obj, indent=2)
            assert json.loads(serialized) == obj, f"{path} failed round-trip JSON serialization"
