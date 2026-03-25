"""CLI device commands: register, approve, list, revoke."""
from __future__ import annotations

import json
import platform
import sys

import httpx

from vaultdotenv.config import get_flag, get_vault_key, get_vault_url
from vaultdotenv.crypto import hash_device_secret, parse_vault_key, sign
from vaultdotenv.device import load_device_secret, register_device


def register(args: list[str]) -> None:
    """Register this device with the vault."""
    vault_key = get_vault_key(args)
    if not vault_key:
        print("Error: No VAULT_KEY found.")
        sys.exit(1)

    vault_url = get_vault_url(args)
    device_name = get_flag(args, "name") or platform.node()

    result = register_device(vault_key, vault_url, device_name)
    print(f"Device registered: {result['status']}")
    if result["status"] == "approved":
        print("This device is auto-approved (first device = owner).")
    else:
        print("Device is pending approval. Ask the project owner to run:")
        print(f"  vde approve-device --id {result['device_id']}")


def approve(args: list[str]) -> None:
    """Approve a pending device."""
    vault_key = get_vault_key(args)
    if not vault_key:
        print("Error: No VAULT_KEY found.")
        sys.exit(1)

    device_id = get_flag(args, "id")
    if not device_id:
        print("Usage: vde approve-device --id DEVICE_ID")
        sys.exit(1)

    vault_url = get_vault_url(args)
    parsed = parse_vault_key(vault_key)
    device_secret = load_device_secret(parsed["project_id"]) if parsed else None

    body = json.dumps({"project_id": parsed["project_id"], "device_id": device_id})
    sig = sign(vault_key, body, device_secret)

    resp = httpx.post(
        f"{vault_url}/api/v1/devices/approve",
        content=body,
        headers={
            "Content-Type": "application/json",
            "X-Vault-Signature": sig,
        },
    )

    if not resp.is_success:
        print(f"Error: {resp.text}")
        sys.exit(1)

    print(f"Device {device_id} approved.")


def list_devices(args: list[str]) -> None:
    """List all registered devices."""
    vault_key = get_vault_key(args)
    if not vault_key:
        print("Error: No VAULT_KEY found.")
        sys.exit(1)

    vault_url = get_vault_url(args)
    parsed = parse_vault_key(vault_key)
    device_secret = load_device_secret(parsed["project_id"]) if parsed else None

    body = json.dumps({"project_id": parsed["project_id"]})
    sig = sign(vault_key, body, device_secret)

    resp = httpx.post(
        f"{vault_url}/api/v1/devices/list",
        content=body,
        headers={
            "Content-Type": "application/json",
            "X-Vault-Signature": sig,
        },
    )

    if not resp.is_success:
        print(f"Error: {resp.text}")
        sys.exit(1)

    devices = resp.json().get("devices", [])
    if not devices:
        print("No devices registered.")
        return

    STATUS_ICONS = {"approved": "\u2713", "pending": "\u23f3", "revoked": "\u2717"}

    print("Devices:\n")
    for d in devices:
        icon = STATUS_ICONS.get(d["status"], "?")
        last_seen = d.get("last_seen_at") or "never"
        print(f"  {icon} {d['device_name']}  ({d['status']})  id: {d['id']}  last seen: {last_seen}")


def revoke(args: list[str]) -> None:
    """Revoke a device's access."""
    vault_key = get_vault_key(args)
    if not vault_key:
        print("Error: No VAULT_KEY found.")
        sys.exit(1)

    device_id = get_flag(args, "id")
    if not device_id:
        print("Usage: vde revoke-device --id DEVICE_ID")
        sys.exit(1)

    vault_url = get_vault_url(args)
    parsed = parse_vault_key(vault_key)
    device_secret = load_device_secret(parsed["project_id"]) if parsed else None

    body = json.dumps({"project_id": parsed["project_id"], "device_id": device_id})
    sig = sign(vault_key, body, device_secret)

    resp = httpx.post(
        f"{vault_url}/api/v1/devices/revoke",
        content=body,
        headers={
            "Content-Type": "application/json",
            "X-Vault-Signature": sig,
        },
    )

    if not resp.is_success:
        print(f"Error: {resp.text}")
        sys.exit(1)

    print(f"Device {device_id} revoked.")
