"""Optional compatibility checks against the separately maintained client."""

import os
from pathlib import Path

import pytest


@pytest.fixture(scope="module")
def external_streaming_client():
    setting = os.environ.get("REMOTE_SANDBOX_CLIENT")
    if not setting:
        pytest.skip("Set REMOTE_SANDBOX_CLIENT to the shared remote_sandbox_exec.py")
    path = Path(setting).expanduser().resolve()
    if not path.is_file():
        pytest.fail(f"REMOTE_SANDBOX_CLIENT does not name a file: {path}")
    return path
