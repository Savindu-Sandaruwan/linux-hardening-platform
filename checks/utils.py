"""Shared helpers: safe file backup, safe file editing, command running."""
import shutil
import subprocess
import datetime
import os

BACKUP_DIR = os.path.join(os.path.dirname(__file__), "..", "backups")


def backup_file(path: str) -> str:
    """Copy a file to backups/ with a timestamp before we ever modify it."""
    os.makedirs(BACKUP_DIR, exist_ok=True)
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = os.path.basename(path) + f".{timestamp}.bak"
    dest = os.path.join(BACKUP_DIR, filename)
    shutil.copy2(path, dest)
    return dest


def run(cmd: list, check=False) -> subprocess.CompletedProcess:
    """Run a shell command safely, capturing output."""
    return subprocess.run(cmd, capture_output=True, text=True, check=check)


def read_file(path: str) -> str:
    with open(path, "r") as f:
        return f.read()


def write_file(path: str, content: str):
    with open(path, "w") as f:
        f.write(content)
