"""CLI init command: create a new vault project."""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import httpx

from vaultdotenv.config import get_auth, get_flag, get_vault_url
from vaultdotenv.crypto import derive_key, generate_device_secret, hash_device_secret, sign, SALT_AUTH
from vaultdotenv.device import register_device


def init(args: list[str]) -> None:
    """Initialize a new vault project."""
    vault_url = get_vault_url(args)
    project_name = get_flag(args, "name") or Path.cwd().name

    # Check for existing VAULT_KEY
    env_path = Path(".env")
    if env_path.exists():
        content = env_path.read_text()
        if "VAULT_KEY=" in content:
            print("Error: VAULT_KEY already exists in .env. This project is already initialized.")
            sys.exit(1)

    print(f"Creating project: {project_name}")

    # Create project
    body = json.dumps({"project_name": project_name})
    resp = httpx.post(
        f"{vault_url}/api/v1/project/create",
        content=body,
        headers={"Content-Type": "application/json"},
    )

    if not resp.is_success:
        print(f"Error: Failed to create project ({resp.status_code}): {resp.text}")
        sys.exit(1)

    data = resp.json()
    project_id = data["project_id"]
    environments = data.get("environments", [])

    # Generate vault key
    secret = os.urandom(32).hex()
    vault_key = f"vk_{project_id}_{secret}"

    # Derive and set auth key hash
    auth_key = derive_key(vault_key, SALT_AUTH)
    auth_key_hash = auth_key.hex()

    sig = sign(vault_key, json.dumps({"project_id": project_id, "auth_key_hash": auth_key_hash}))
    set_body = json.dumps({"project_id": project_id, "auth_key_hash": auth_key_hash})
    resp = httpx.post(
        f"{vault_url}/api/v1/project/set-key",
        content=set_body,
        headers={
            "Content-Type": "application/json",
            "X-Vault-Signature": sig,
        },
    )

    if not resp.is_success:
        print(f"Error: Failed to set auth key ({resp.status_code}): {resp.text}")
        sys.exit(1)

    # Register device (first device = auto-approved owner)
    result = register_device(vault_key, vault_url)
    print(f"Device registered: {result['status']}")

    # Link to dashboard if logged in
    auth = get_auth()
    if auth and auth.get("token"):
        try:
            link_resp = httpx.post(
                f"{vault_url}/api/v1/dashboard/projects/link",
                content=json.dumps({"project_id": project_id}),
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {auth['token']}",
                },
            )
            if link_resp.is_success:
                print("Linked to dashboard account.")
        except Exception:
            pass

    # Write VAULT_KEY to .env
    with open(env_path, "a") as f:
        if env_path.exists() and env_path.read_text() and not env_path.read_text().endswith("\n"):
            f.write("\n")
        f.write(f"VAULT_KEY={vault_key}\n")

    print(f"\nProject created: {project_name}")
    print(f"Project ID: {project_id}")
    print(f"Environments: {', '.join(environments)}")
    print(f"VAULT_KEY written to .env")
    print("\nNext steps:")
    print("  vde push          Push your .env secrets to vault")
    print("  vde pull           Pull secrets from vault")
