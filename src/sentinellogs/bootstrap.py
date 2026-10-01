from __future__ import annotations

import os
import secrets
from pathlib import Path


def ensure_local_secrets() -> Path:
    """Create and load per-installation secrets without network access."""
    config_dir = Path(os.environ.get("SENTINELLOGS_CONFIG_DIR", ".sentinellogs"))
    config_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    secret_path = config_dir / "secrets.env"
    if not secret_path.exists():
        username = os.environ.get("SENTINELLOGS_AUTH_USER", "sentinellogs")
        password = secrets.token_urlsafe(32)
        tenant_token = secrets.token_urlsafe(48)
        secret_path.write_text(
            f"SENTINELLOGS_BASIC_AUTH={username}:{password}\n"
            f"SENTINELLOGS_TENANT_TOKENS=local:{tenant_token}\n",
            encoding="utf-8",
        )
        secret_path.chmod(0o600)

    for line in secret_path.read_text(encoding="utf-8").splitlines():
        name, separator, value = line.partition("=")
        if separator and name and name not in os.environ:
            os.environ[name] = value
    return secret_path