"""Optional compatibility checks against the separately maintained client."""

import os
from pathlib import Path

import pytest


@pytest.fixture(scope="module")
def external_streaming_client():
    setting = os.environ.get("EXTERNAL_SANDBOX_CLIENT")
    if not setting:
        pytest.skip("Set EXTERNAL_SANDBOX_CLIENT to the shared external_sandbox_exec.py")
    path = Path(setting).expanduser().resolve()
    if not path.is_file():
        pytest.fail(f"EXTERNAL_SANDBOX_CLIENT does not name a file: {path}")
    return path
