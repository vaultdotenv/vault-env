"""CLI auth commands: login, logout, whoami."""
from __future__ import annotations

import sys
import time
import webbrowser

import httpx

from vaultdotenv.config import get_auth, get_vault_url, remove_auth, save_auth


def login(args: list[str]) -> None:
    """Browser-based login flow — opens browser, polls for approval."""
    vault_url = get_vault_url(args)

    resp = httpx.post(f"{vault_url}/api/v1/cli/auth/start")
    if not resp.is_success:
        print(f"Error: Failed to start auth ({resp.status_code})")
        sys.exit(1)

    data = resp.json()
    code = data["code"]
    auth_url = data["auth_url"]

    print(f"\nYour auth code: {code}\n")
    print(f"Opening browser to: {auth_url}")
    print("Waiting for approval...\n")

    try:
        webbrowser.open(auth_url)
    except Exception:
        print(f"Could not open browser. Visit: {auth_url}")

    for _ in range(120):
        time.sleep(5)
        poll = httpx.get(f"{vault_url}/api/v1/cli/auth/poll", params={"code": code})
        if not poll.is_success:
            continue

        result = poll.json()
        status = result.get("status")

        if status == "approved":
            token = result["token"]
            user = result.get("user", {})
            save_auth({"token": token, "email": user.get("email"), "api_url": vault_url})
            print(f"Logged in as {user.get('email', 'unknown')}")
            return

        if status == "expired":
            print("Error: Auth code expired. Try again.")
            sys.exit(1)

    print("Error: Timed out waiting for approval.")
    sys.exit(1)


def logout(args: list[str]) -> None:
    """Remove saved auth token."""
    remove_auth()
    print("Logged out.")


def whoami(args: list[str]) -> None:
    """Show current logged-in user."""
    auth = get_auth()
    if not auth or not auth.get("token"):
        print("Not logged in. Run: vde login")
        sys.exit(1)
    print(f"Logged in as: {auth.get('email', 'unknown')}")
    print(f"API: {auth.get('api_url', 'default')}")
