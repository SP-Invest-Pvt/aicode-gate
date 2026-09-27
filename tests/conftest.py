import subprocess
from pathlib import Path

import pytest


def git(repo: Path, *args: str, author: str = "sankalp") -> None:
    env_args = ["-c", f"user.name={author}", "-c", "user.email=dev@example.com",
                "-c", "commit.gpgsign=false", "-c", "core.autocrlf=false"]
    subprocess.run(["git", *env_args, "-C", str(repo), *args], check=True, capture_output=True)


def write(repo: Path, path: str, lines: list[str]) -> None:
    p = repo / path
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("".join(line + "\n" for line in lines), encoding="utf-8")


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    """Three crafted commits.

    1. human (sankalp):              src/auth/login.py lines 1-10, src/payments/pay.py lines 1-4
    2. sankalp + Co-Authored-By trailer: appends 6 lines to src/auth/login.py        -> AI
    3. bot author "Copilot":          appends 4 lines to pay.py, adds src/util.py (5) -> AI
    """
    r = tmp_path / "repo"
    r.mkdir()
    git(r, "init", "-q", "-b", "main")
    write(r, "src/auth/login.py", [f"human_login_{i} = {i}" for i in range(1, 11)])
    write(r, "src/payments/pay.py", [f"human_pay_{i} = {i}" for i in range(1, 5)])
    git(r, "add", "-A")
    git(r, "commit", "-q", "-m", "feat: login and payments skeleton")

    write(r, "src/auth/login.py", [f"human_login_{i} = {i}" for i in range(1, 11)]
          + [f"ai_login_{i} = {i}" for i in range(1, 7)])
    git(r, "add", "-A")
    git(r, "commit", "-q", "-m", "feat: token check\n\nCo-Authored-By: Claude <noreply@anthropic.com>")

    write(r, "src/payments/pay.py", [f"human_pay_{i} = {i}" for i in range(1, 5)]
          + [f"bot_pay_{i} = {i}" for i in range(1, 5)])
    write(r, "src/util.py", [f"bot_util_{i} = {i}" for i in range(1, 6)])
    git(r, "add", "-A")
    git(r, "commit", "-q", "-m", "fix: retry payments", author="Copilot")
    return r
