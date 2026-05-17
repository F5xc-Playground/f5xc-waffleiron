"""Tests for the WaffleIron CLI."""

from typer.testing import CliRunner

from waffleiron_cli.main import app

runner = CliRunner()


class TestConvert:
    def test_basic_conversion(self, fixtures_path, tmp_path):
        result = runner.invoke(app, [
            "convert", str(fixtures_path / "minimal_blocking.xml"),
            "--namespace", "test-ns",
            "--output", str(tmp_path / "output"),
        ])
        assert result.exit_code == 0, result.output
        assert (tmp_path / "output" / "app_firewall.json").exists()
        assert (tmp_path / "output" / "gap_report.md").exists()
        assert (tmp_path / "output" / "decisions.yaml").exists()

    def test_with_bulk_alarm_only(self, fixtures_path, tmp_path):
        result = runner.invoke(app, [
            "convert", str(fixtures_path / "mature_tuned.xml"),
            "--namespace", "test-ns",
            "--output", str(tmp_path / "output"),
            "--alarm-only-signatures=exclude",
        ])
        assert result.exit_code == 0, result.output

    def test_with_decisions_file(self, fixtures_path, tmp_path):
        # First analyze to generate decisions file
        runner.invoke(app, [
            "analyze", str(fixtures_path / "mature_tuned.xml"),
            "--output", str(tmp_path / "analysis"),
        ])
        decisions_path = tmp_path / "analysis" / "decisions.yaml"
        assert decisions_path.exists()
        # Then convert with decisions
        result = runner.invoke(app, [
            "convert", str(fixtures_path / "mature_tuned.xml"),
            "--namespace", "test-ns",
            "--output", str(tmp_path / "output"),
            "--decisions", str(decisions_path),
        ])
        assert result.exit_code == 0, result.output


class TestAnalyze:
    def test_produces_report_and_decisions(self, fixtures_path, tmp_path):
        result = runner.invoke(app, [
            "analyze", str(fixtures_path / "mature_tuned.xml"),
            "--output", str(tmp_path / "output"),
        ])
        assert result.exit_code == 0, result.output
        assert (tmp_path / "output" / "gap_report.md").exists()
        assert (tmp_path / "output" / "gap_report.json").exists()
        assert (tmp_path / "output" / "decisions.yaml").exists()


class TestValidate:
    def test_valid_output(self, fixtures_path, tmp_path):
        # Generate output first
        runner.invoke(app, [
            "convert", str(fixtures_path / "minimal_blocking.xml"),
            "--namespace", "ns", "--output", str(tmp_path / "output"),
        ])
        result = runner.invoke(app, ["validate", str(tmp_path / "output")])
        assert result.exit_code == 0, result.output


class TestPush:
    def test_push_no_creds(self, tmp_path):
        result = runner.invoke(app, ["push", str(tmp_path)])
        assert result.exit_code == 1
        assert "No XC credentials" in result.output

    def test_push_no_files(self, tmp_path):
        result = runner.invoke(app, [
            "push", str(tmp_path),
            "--tenant-url", "https://example.console.ves.volterra.io",
            "--api-token", "fake",
        ])
        assert result.exit_code == 1
        assert "No pushable JSON" in result.output

    def test_push_dry_run(self, fixtures_path, tmp_path):
        runner.invoke(app, [
            "convert", str(fixtures_path / "minimal_blocking.xml"),
            "--namespace", "test-ns", "--output", str(tmp_path / "output"),
        ])
        result = runner.invoke(app, [
            "push", str(tmp_path / "output"),
            "--tenant-url", "https://example.console.ves.volterra.io",
            "--api-token", "fake",
            "--dry-run",
        ])
        assert result.exit_code == 0, result.output
        assert "would push" in result.output
        assert "app_firewall.json" in result.output


class TestXcStatus:
    def test_xc_status_no_creds(self):
        result = runner.invoke(app, ["xc-status"])
        assert result.exit_code == 1
        assert "No XC credentials" in result.output


class TestMissingFile:
    def test_nonexistent_file(self, tmp_path):
        result = runner.invoke(app, [
            "convert", str(tmp_path / "nonexistent.xml"),
            "--namespace", "ns", "--output", str(tmp_path / "output"),
        ])
        assert result.exit_code != 0
