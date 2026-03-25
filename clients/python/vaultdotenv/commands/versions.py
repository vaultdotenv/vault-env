"""CLI version commands: versions, rollback."""
from __future__ import annotations

import json
import sys

import httpx

from vaultdotenv.config import get_environment, get_flag, get_vault_key, get_vault_url
from vaultdotenv.crypto import parse_vault_key, sign


def versions(args: list[str]) -> None:
    """List secret versions."""
    vault_key = get_vault_key(args)
    if not vault_key:
        print("Error: No VAULT_KEY found.")
        sys.exit(1)

    env = get_environment(args)
    vault_url = get_vault_url(args)
    parsed = parse_vault_key(vault_key)

    body = json.dumps({"project_id": parsed["project_id"], "environment": env})
    sig = sign(vault_key, body)

    resp = httpx.post(
        f"{vault_url}/api/v1/secrets/versions",
        content=body,
        headers={
            "Content-Type": "application/json",
            "X-Vault-Signature": sig,
        },
    )

    if not resp.is_success:
        print(f"Error: {resp.text}")
        sys.exit(1)

    data = resp.json()
    vers = data.get("versions", [])

    if not vers:
        print(f"No versions found for {env}")
        return

    print(f"Versions ({env}):\n")
    for v in vers:
        changed = v.get("changed_keys") or []
        n_changed = len(changed) if isinstance(changed, list) else 0
        print(f"  v{v['version']}  {v['created_at']}  ({n_changed} keys changed)")


def rollback(args: list[str]) -> None:
    """Rollback to a specific version."""
    vault_key = get_vault_key(args)
    if not vault_key:
        print("Error: No VAULT_KEY found.")
        sys.exit(1)

    version = get_flag(args, "version")
    if not version:
        print("Usage: vde rollback --version N [--env ENV]")
        sys.exit(1)

    env = get_environment(args)
    vault_url = get_vault_url(args)
    parsed = parse_vault_key(vault_key)

    body = json.dumps({
        "project_id": parsed["project_id"],
        "environment": env,
        "version": int(version),
    })
    sig = sign(vault_key, body)

    resp = httpx.post(
        f"{vault_url}/api/v1/secrets/rollback",
        content=body,
        headers={
            "Content-Type": "application/json",
            "X-Vault-Signature": sig,
        },
    )

    if not resp.is_success:
        print(f"Error: {resp.text}")
        sys.exit(1)

    data = resp.json()
    print(f"Rolled back {env} to v{data.get('version', version)}")
