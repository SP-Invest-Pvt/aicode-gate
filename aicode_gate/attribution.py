"""Decide, line by line, whether code came from an AI-attributed commit.

A commit is AI-attributed when its author (lowercased) is in `bots`, or its message contains
one of `ai_markers` (case-insensitive), or `author_origin` maps the author to `ai`. Each line's
commit comes from `git blame --line-porcelain`. Lines from other commits count as human; lines
whose author is not listed anywhere are also counted as "unknown origin" so a policy can insist
on a complete author map.

This is a heuristic: it sees only what commit metadata admits to. See the README.
"""
from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from . import GateError

DEFAULT_ATTRIBUTION = {
    "bots": ["claude", "copilot", "cursor"],
    "ai_markers": ["Co-Authored-By: Claude", "generated with", "AI-assisted"],
    "author_origin": {},
}
ORIGINS = ("ai", "human")
UNCOMMITTED = "0" * 40
_BLAME_HEADER = re.compile(r"^([0-9a-f]{40}) \d+ \d+")


@dataclass
class AttributionConfig:
    bots: list[str]
    ai_markers: list[str]
    author_origin: dict[str, str]


@dataclass
class Commit:
    sha: str
    author: str
    origin: str  # "ai" or "human"
    known: bool  # author or marker accounted for by the config


@dataclass
class FileAttribution:
    path: str
    line_origins: list[str] = field(default_factory=list)  # index 0 is line 1
    unknown_lines: int = 0

    @property
    def total(self) -> int:
        return len(self.line_origins)

    @property
    def ai_lines(self) -> int:
        return sum(1 for o in self.line_origins if o == "ai")

    @property
    def human_lines(self) -> int:
        return self.total - self.ai_lines

    @property
    def ai_ratio(self) -> float:
        return self.ai_lines / self.total if self.total else 0.0

    def origin_of(self, line: int) -> str:
        """Origin of a 1-based line; out-of-range lines count as human."""
        return self.line_origins[line - 1] if 1 <= line <= self.total else "human"


def load_attribution_config(path: str | Path | None) -> AttributionConfig:
    raw = dict(DEFAULT_ATTRIBUTION)
    if path is not None:
        try:
            doc = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
        except FileNotFoundError:
            raise GateError(f"file not found: {path}") from None
        except yaml.YAMLError as e:
            raise GateError(f"{path}: invalid YAML ({e})") from None
        if not isinstance(doc, dict):
            raise GateError(f"{path}: expected a mapping")
        unknown = set(doc) - set(DEFAULT_ATTRIBUTION)
        if unknown:
            raise GateError(f"{path}: unknown key(s): {', '.join(sorted(unknown))}")
        raw.update(doc)
    for key in ("bots", "ai_markers"):
        if not isinstance(raw[key], list) or not all(isinstance(x, str) and x for x in raw[key]):
            raise GateError(f"attribution: {key} must be a list of non-empty strings")
    origin = raw["author_origin"] or {}
    if not isinstance(origin, dict) or not all(v in ORIGINS for v in origin.values()):
        raise GateError("attribution: author_origin must map author names to 'ai' or 'human'")
    return AttributionConfig([b.lower() for b in raw["bots"]], list(raw["ai_markers"]),
                             {str(k).lower(): v for k, v in origin.items()})


def classify_commit(author: str, message: str, cfg: AttributionConfig) -> tuple[str, bool]:
    """Return (origin, known) for one commit."""
    who = author.strip().lower()
    text = message.lower()
    if who in cfg.bots or cfg.author_origin.get(who) == "ai":
        return "ai", True
    if any(m.lower() in text for m in cfg.ai_markers):
        return "ai", True
    return "human", who in cfg.author_origin


def git(repo: str | Path, *args: str) -> str:
    try:
        proc = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, check=False)
    except FileNotFoundError:
        raise GateError("git is not installed or not on PATH") from None
    if proc.returncode != 0:
        msg = proc.stderr.decode("utf-8", "replace").strip().splitlines()
        raise GateError(f"git {args[0]} failed in {repo}: {msg[0] if msg else 'exit ' + str(proc.returncode)}")
    return proc.stdout.decode("utf-8", "replace")


def commit_origins(repo: str | Path, cfg: AttributionConfig) -> dict[str, Commit]:
    """Classify every commit reachable from HEAD. Reads subject and body (trailers live in the body)."""
    out = git(repo, "log", "--format=%H%x1f%an%x1f%B%x1e")
    commits = {}
    for record in out.split("\x1e"):
        record = record.strip("\n")
        if not record:
            continue
        sha, author, message = (record.split("\x1f") + ["", ""])[:3]
        origin, known = classify_commit(author, message, cfg)
        commits[sha] = Commit(sha, author, origin, known)
    return commits


def blame_file(repo: str | Path, path: str) -> list[str]:
    """Commit sha for each line of path at HEAD's working tree (uncommitted lines get 40 zeros)."""
    shas = []
    current = None
    for line in git(repo, "blame", "--line-porcelain", "--", path).splitlines():
        m = _BLAME_HEADER.match(line)
        if m:
            current = m.group(1)
        elif line.startswith("\t"):
            shas.append(current or UNCOMMITTED)
    return shas


def tracked_files(repo: str | Path, prefixes: list[str] | None = None) -> list[str]:
    files = [f for f in git(repo, "ls-files", "-z").split("\0") if f]
    if prefixes:
        files = [f for f in files if any(f.startswith(p) for p in prefixes)]
    return files


def _is_text(repo: str | Path, path: str) -> bool:
    try:
        with open(Path(repo) / path, "rb") as fh:
            return b"\0" not in fh.read(8192)
    except OSError:
        return False


def attribute(repo: str | Path, cfg: AttributionConfig, prefixes: list[str] | None = None,
              files: list[str] | None = None) -> dict[str, FileAttribution]:
    """Per-file line origins for tracked text files (optionally only under prefixes, or only files)."""
    commits = commit_origins(repo, cfg)
    result = {}
    for path in (files if files is not None else tracked_files(repo, prefixes)):
        if not _is_text(repo, path):
            continue
        fa = FileAttribution(path)
        for sha in blame_file(repo, path):
            c = commits.get(sha)
            fa.line_origins.append(c.origin if c else "human")
            if c is None or not c.known:
                fa.unknown_lines += 1
        result[path] = fa
    return result
