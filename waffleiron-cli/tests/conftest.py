from pathlib import Path

import pytest


@pytest.fixture
def fixtures_path():
    """Path to the shared test fixtures in the waffleiron library."""
    return Path(__file__).resolve().parent.parent.parent / "waffleiron" / "tests" / "fixtures"
