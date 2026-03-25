"""CLI secret commands: push, pull, set, delete, get."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import httpx

from vaultdotenv.client import pull_secrets, push_secrets, _parse_dotenv
from vaultdotenv.config import get_environment, get_flag, get_vault_key, get_vault_url
from vaultdotenv.crypto import hash_device_secret, parse_vault_key, sign
from vaultdotenv.device import load_device_secret


def _mask(value: str) -> str:
    if len(value) <= 8:
        return "****"
    return value[:4] + "..." + value[-4:]


def push(args: list[str]) -> None:
    """Push .env secrets to vault."""
    vault_key = get_vault_key(args)
    if not vault_key:
        print("Error: No VAULT_KEY found. Run: vde init")
        sys.exit(1)

    env = get_environment(args)
    vault_url = get_vault_url(args)
    file_path = Path(get_flag(args, "file") or ".env")

    if not file_path.exists():
        print(f"Error: {file_path} not found")
        sys.exit(1)

    secrets = _parse_dotenv(file_path.read_text())
    secrets.pop("VAULT_KEY", None)

    if not secrets:
        print("No secrets to push (empty .env or only VAULT_KEY).")
        return

    # Diff against current version
    changed_keys = []
    try:
        current = pull_secrets(vault_key, env, vault_url)
        old = current["secrets"]
        for k in secrets:
            if k not in old:
                changed_keys.append(f"+{k}")
            elif secrets[k] != old[k]:
                changed_keys.append(f"~{k}")
        for k in old:
            if k not in secrets:
                changed_keys.append(f"-{k}")
    except Exception:
        changed_keys = [f"+{k}" for k in secrets]

    result = push_secrets(vault_key, secrets, env, vault_url)
    version = result.get("version", "?")

    print(f"Pushed {len(secrets)} secrets to {env} (v{version})")
    if changed_keys:
        for ck in changed_keys:
            print(f"  {ck}")


def pull(args: list[str]) -> None:
    """Pull secrets from vault."""
    vault_key = get_vault_key(args)
    if not vault_key:
        print("Error: No VAULT_KEY found. Run: vde init")
        sys.exit(1)

    env = get_environment(args)
    vault_url = get_vault_url(args)
    output = get_flag(args, "output")

    result = pull_secrets(vault_key, env, vault_url)
    secrets = result["secrets"]
    version = result["version"]

    if output:
        lines = [f"{k}={v}" for k, v in sorted(secrets.items())]
        Path(output).write_text("\n".join(lines) + "\n")
        print(f"Wrote {len(secrets)} secrets to {output} (v{version})")
    else:
        print(f"Secrets ({env}, v{version}):\n")
        for k, v in sorted(secrets.items()):
            print(f"  {k}={_mask(str(v))}")


def set_secret(args: list[str]) -> None:
    """Set a single secret."""
    vault_key = get_vault_key(args)
    if not vault_key:
        print("Error: No VAULT_KEY found.")
        sys.exit(1)

    # Parse: vde set KEY "value"
    positional = [a for a in args[1:] if not a.startswith("--")]
    positional = [a for i, a in enumerate(args[1:]) if not args[i].startswith("--") and not a.startswith("--")]

    # Simpler: find KEY and VALUE after 'set'
    key = args[1] if len(args) > 1 and not args[1].startswith("--") else None
    value = args[2] if len(args) > 2 and not args[2].startswith("--") else None

    if not key or value is None:
        print("Usage: vde set KEY \"value\" [--env ENV]")
        sys.exit(1)

    env = get_environment(args)
    vault_url = get_vault_url(args)

    try:
        current = pull_secrets(vault_key, env, vault_url)
        secrets = current["secrets"]
    except Exception:
        secrets = {}

    is_new = key not in secrets
    secrets[key] = value

    push_secrets(vault_key, secrets, env, vault_url)
    print(f"{'Added' if is_new else 'Updated'}: {key}")


def delete(args: list[str]) -> None:
    """Delete a secret with confirmation."""
    vault_key = get_vault_key(args)
    if not vault_key:
        print("Error: No VAULT_KEY found.")
        sys.exit(1)

    key = args[1] if len(args) > 1 and not args[1].startswith("--") else None
    if not key:
        print("Usage: vde delete KEY [--env ENV]")
        sys.exit(1)

    env = get_environment(args)
    vault_url = get_vault_url(args)
    confirm = "--confirm" in args

    current = pull_secrets(vault_key, env, vault_url)
    secrets = current["secrets"]

    if key not in secrets:
        print(f"Error: Key '{key}' not found in {env}")
        sys.exit(1)

    if not confirm:
        answer = input(f"Type '{key}' to confirm deletion: ")
        if answer != key:
            print("Cancelled.")
            return

    del secrets[key]
    push_secrets(vault_key, secrets, env, vault_url)
    print(f"Deleted: {key}")


def get(args: list[str]) -> None:
    """Get a single secret (masked by default)."""
    vault_key = get_vault_key(args)
    if not vault_key:
        print("Error: No VAULT_KEY found.")
        sys.exit(1)

    key = args[1] if len(args) > 1 and not args[1].startswith("--") else None
    if not key:
        print("Usage: vde get KEY [--env ENV] [--raw --token TOKEN]")
        sys.exit(1)

    env = get_environment(args)
    vault_url = get_vault_url(args)
    raw = "--raw" in args
    token = get_flag(args, "token")

    result = pull_secrets(vault_key, env, vault_url)
    secrets = result["secrets"]

    if key not in secrets:
        print(f"Error: Key '{key}' not found in {env}")
        sys.exit(1)

    value = str(secrets[key])

    if raw and token:
        # Validate reveal token
        parsed = parse_vault_key(vault_key)
        device_secret = load_device_secret(parsed["project_id"]) if parsed else None

        body = json.dumps({"project_id": parsed["project_id"], "token": token})
        sig = sign(vault_key, body, device_secret)

        resp = httpx.post(
            f"{vault_url}/api/v1/reveal-token/validate",
            content=body,
            headers={
                "Content-Type": "application/json",
                "X-Vault-Signature": sig,
            },
        )

        if resp.is_success and resp.json().get("valid"):
            print(value)
        else:
            reason = resp.json().get("reason", "invalid") if resp.is_success else "error"
            print(f"Error: Reveal token {reason}")
            sys.exit(1)
    elif raw:
        print("Error: --raw requires --token. Create one in the dashboard.")
        sys.exit(1)
    else:
        print(f"{key}={_mask(value)}")
