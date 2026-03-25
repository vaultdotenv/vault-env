"""CLI configuration — paths, flag parsing, auth token management."""
from __future__ import annotations

import json
import os
import stat
from pathlib import Path

DEFAULT_VAULT_URL = "https://api.vaultdotenv.io"
VAULT_DIR = Path.home() / ".vault"
KEYS_DIR = VAULT_DIR / "keys"
AUTH_PATH = VAULT_DIR / "auth.json"


def get_flag(args: list[str], name: str) -> str | None:
    """Parse --flag value from args list."""
    flag = f"--{name}"
    for i, arg in enumerate(args):
        if arg == flag and i + 1 < len(args):
            return args[i + 1]
    return None


def get_vault_key(args: list[str]) -> str | None:
    """Resolve vault key from --project saved key, VAULT_KEY env, or .env file."""
    project = get_flag(args, "project")
    if project:
        key_path = KEYS_DIR / f"{project}.key"
        if key_path.exists():
            return key_path.read_text().strip()
        print(f"Error: No saved key for project '{project}'. Run: vde key save --project {project} --key vk_...")
        return None

    vault_key = os.environ.get("VAULT_KEY")
    if vault_key:
        return vault_key

    env_path = Path(".env")
    if env_path.exists():
        for line in env_path.read_text().splitlines():
            line = line.strip()
            if line.startswith("VAULT_KEY="):
                return line.split("=", 1)[1].strip().strip("'\"")

    return None


def get_vault_url(args: list[str]) -> str:
    """Resolve vault URL from --url flag, VAULT_URL env, or default."""
    return get_flag(args, "url") or os.environ.get("VAULT_URL") or DEFAULT_VAULT_URL


def get_environment(args: list[str]) -> str:
    """Resolve environment from --env flag, env vars, or default."""
    return (
        get_flag(args, "env")
        or os.environ.get("NODE_ENV")
        or os.environ.get("ENVIRONMENT")
        or "development"
    )


def get_auth() -> dict | None:
    """Load CLI auth token from ~/.vault/auth.json."""
    if not AUTH_PATH.exists():
        return None
    try:
        return json.loads(AUTH_PATH.read_text())
    except Exception:
        return None


def save_auth(data: dict) -> None:
    """Save CLI auth token to ~/.vault/auth.json."""
    VAULT_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    AUTH_PATH.write_text(json.dumps(data))
    AUTH_PATH.chmod(stat.S_IRUSR | stat.S_IWUSR)


def remove_auth() -> None:
    """Delete auth token file."""
    if AUTH_PATH.exists():
        AUTH_PATH.unlink()
