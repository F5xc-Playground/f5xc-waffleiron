"""Tests for XC client configuration (xc_client/config.py)."""

import pytest

from waffleiron.xc_client.config import XCConfig


class TestTokenAuth:
    def test_from_env(self, monkeypatch):
        monkeypatch.setenv("F5XC_TENANT_URL", "https://tenant.console.ves.volterra.io")
        monkeypatch.setenv("F5XC_API_TOKEN", "test-token")
        monkeypatch.delenv("F5XC_API_TOKEN_FILE", raising=False)
        monkeypatch.delenv("F5XC_P12_PATH", raising=False)
        monkeypatch.delenv("F5XC_P12_PASSWORD", raising=False)
        config = XCConfig.from_env()
        assert config.tenant_url == "https://tenant.console.ves.volterra.io"
        assert config.api_token == "test-token"
        assert config.auth_method == "token"

    def test_token_file(self, monkeypatch, tmp_path):
        token_file = tmp_path / "api-token"
        token_file.write_text("file-token")
        monkeypatch.setenv("F5XC_TENANT_URL", "https://t.example.com")
        monkeypatch.setenv("F5XC_API_TOKEN_FILE", str(token_file))
        monkeypatch.delenv("F5XC_API_TOKEN", raising=False)
        monkeypatch.delenv("F5XC_P12_PATH", raising=False)
        monkeypatch.delenv("F5XC_P12_PASSWORD", raising=False)
        config = XCConfig.from_env()
        assert config.api_token == "file-token"

    def test_file_takes_precedence(self, monkeypatch, tmp_path):
        token_file = tmp_path / "api-token"
        token_file.write_text("file-token")
        monkeypatch.setenv("F5XC_TENANT_URL", "https://t.example.com")
        monkeypatch.setenv("F5XC_API_TOKEN", "env-token")
        monkeypatch.setenv("F5XC_API_TOKEN_FILE", str(token_file))
        monkeypatch.delenv("F5XC_P12_PATH", raising=False)
        monkeypatch.delenv("F5XC_P12_PASSWORD", raising=False)
        config = XCConfig.from_env()
        assert config.api_token == "file-token"


class TestP12Auth:
    def test_from_env(self, monkeypatch, tmp_path):
        p12 = tmp_path / "api-creds.p12"
        p12.write_bytes(b"fake-p12")
        monkeypatch.setenv("F5XC_TENANT_URL", "https://t.example.com")
        monkeypatch.setenv("F5XC_P12_PATH", str(p12))
        monkeypatch.setenv("F5XC_P12_PASSWORD", "pass")
        monkeypatch.delenv("F5XC_API_TOKEN", raising=False)
        monkeypatch.delenv("F5XC_API_TOKEN_FILE", raising=False)
        config = XCConfig.from_env()
        assert config.auth_method == "p12"
        assert config.p12_path == str(p12)
        assert config.p12_password == "pass"


class TestMutualExclusion:
    def test_both_raises(self, monkeypatch, tmp_path):
        p12 = tmp_path / "api-creds.p12"
        p12.write_bytes(b"fake-p12")
        monkeypatch.setenv("F5XC_TENANT_URL", "https://t.example.com")
        monkeypatch.setenv("F5XC_API_TOKEN", "token")
        monkeypatch.setenv("F5XC_P12_PATH", str(p12))
        monkeypatch.setenv("F5XC_P12_PASSWORD", "pass")
        monkeypatch.delenv("F5XC_API_TOKEN_FILE", raising=False)
        with pytest.raises(ValueError, match="[Mm]utually exclusive"):
            XCConfig.from_env()


class TestNotConfigured:
    def test_no_creds_returns_none(self, monkeypatch):
        monkeypatch.delenv("F5XC_TENANT_URL", raising=False)
        monkeypatch.delenv("F5XC_API_TOKEN", raising=False)
        monkeypatch.delenv("F5XC_API_TOKEN_FILE", raising=False)
        monkeypatch.delenv("F5XC_P12_PATH", raising=False)
        monkeypatch.delenv("F5XC_P12_PASSWORD", raising=False)
        config = XCConfig.from_env()
        assert config is None

    def test_missing_tenant_url_raises(self, monkeypatch):
        monkeypatch.delenv("F5XC_TENANT_URL", raising=False)
        monkeypatch.setenv("F5XC_API_TOKEN", "some-token")
        monkeypatch.delenv("F5XC_API_TOKEN_FILE", raising=False)
        monkeypatch.delenv("F5XC_P12_PATH", raising=False)
        monkeypatch.delenv("F5XC_P12_PASSWORD", raising=False)
        with pytest.raises(ValueError, match="F5XC_TENANT_URL"):
            XCConfig.from_env()

    def test_explicit_token_file_missing_raises(self, monkeypatch, tmp_path):
        nonexistent = tmp_path / "no-such-token"
        monkeypatch.setenv("F5XC_TENANT_URL", "https://t.example.com")
        monkeypatch.setenv("F5XC_API_TOKEN_FILE", str(nonexistent))
        monkeypatch.delenv("F5XC_API_TOKEN", raising=False)
        monkeypatch.delenv("F5XC_P12_PATH", raising=False)
        monkeypatch.delenv("F5XC_P12_PASSWORD", raising=False)
        with pytest.raises(FileNotFoundError):
            XCConfig.from_env()


class TestDefaultPaths:
    def test_default_p12_path(self, monkeypatch):
        monkeypatch.setenv("F5XC_TENANT_URL", "https://t.example.com")
        monkeypatch.setenv("F5XC_P12_PASSWORD", "pass")
        monkeypatch.delenv("F5XC_P12_PATH", raising=False)
        monkeypatch.delenv("F5XC_API_TOKEN", raising=False)
        monkeypatch.delenv("F5XC_API_TOKEN_FILE", raising=False)
        # Default path /certs/api-creds.p12 won't exist in test, so should return None
        config = XCConfig.from_env()
        assert config is None  # file doesn't exist at default path
