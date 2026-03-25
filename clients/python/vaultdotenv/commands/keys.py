"""CLI key management: save, list, remove."""
from __future__ import annotations

import stat
import sys

from vaultdotenv.config import KEYS_DIR, get_flag


def save(args: list[str]) -> None:
    """Save a vault key locally."""
    project = get_flag(args, "project")
    key = get_flag(args, "key")

    if not project or not key:
        print("Usage: vde key save --project NAME --key vk_...")
        sys.exit(1)

    if not key.startswith("vk_"):
        print("Error: Key must start with 'vk_'")
        sys.exit(1)

    KEYS_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    key_path = KEYS_DIR / f"{project}.key"
    key_path.write_text(key + "\n")
    key_path.chmod(stat.S_IRUSR | stat.S_IWUSR)

    print(f"Saved key for project '{project}'")


def list_keys(args: list[str]) -> None:
    """List saved project keys."""
    if not KEYS_DIR.exists():
        print("No saved keys.")
        return

    keys = sorted(KEYS_DIR.glob("*.key"))
    if not keys:
        print("No saved keys.")
        return

    print("Saved keys:\n")
    for k in keys:
        print(f"  {k.stem}")


def remove(args: list[str]) -> None:
    """Remove a saved key."""
    project = get_flag(args, "project")
    if not project:
        print("Usage: vde key remove --project NAME")
        sys.exit(1)

    key_path = KEYS_DIR / f"{project}.key"
    if not key_path.exists():
        print(f"Error: No saved key for project '{project}'")
        sys.exit(1)

    key_path.unlink()
    print(f"Removed key for project '{project}'")
