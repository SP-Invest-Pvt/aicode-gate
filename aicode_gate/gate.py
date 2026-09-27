"""Policy: a ceiling on AI-code vulnerability density in critical paths."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml

from . import GateError
from .density import FileDensity

REQUIRED_KEYS = ("max_ai_density_critical_paths", "critical_paths", "fail_on_unknown_origin")


@dataclass(frozen=True)
class Policy:
    max_ai_density_critical_paths: float
    critical_paths: tuple[str, ...]
    fail_on_unknown_origin: bool


@dataclass(frozen=True)
class Violation:
    file: str
    reason: str
    density_ai: float

    def to_dict(self) -> dict:
        return {"file": self.file, "reason": self.reason, "density_ai": round(self.density_ai, 3)}


def parse_policy(doc) -> Policy:
    if not isinstance(doc, dict):
        raise GateError("policy: expected a mapping")
    missing = [k for k in REQUIRED_KEYS if k not in doc]
    if missing:
        raise GateError(f"policy: missing key(s): {', '.join(missing)}")
    unknown = set(doc) - set(REQUIRED_KEYS)
    if unknown:
        raise GateError(f"policy: unknown key(s): {', '.join(sorted(unknown))}")
    limit = doc["max_ai_density_critical_paths"]
    if isinstance(limit, bool) or not isinstance(limit, (int, float)) or limit < 0:
        raise GateError(f"policy: max_ai_density_critical_paths must be a number >= 0, got {limit!r}")
    paths = doc["critical_paths"]
    if not isinstance(paths, list) or not paths or not all(isinstance(p, str) and p for p in paths):
        raise GateError("policy: critical_paths must be a non-empty list of path prefixes")
    if not isinstance(doc["fail_on_unknown_origin"], bool):
        raise GateError("policy: fail_on_unknown_origin must be true or false")
    return Policy(float(limit), tuple(paths), doc["fail_on_unknown_origin"])


def load_policy(path: str | Path) -> Policy:
    try:
        doc = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise GateError(f"file not found: {path}") from None
    except yaml.YAMLError as e:
        raise GateError(f"{path}: invalid YAML ({e})") from None
    return parse_policy(doc)


def is_critical(path: str, policy: Policy) -> bool:
    return any(path.startswith(p) for p in policy.critical_paths)


def evaluate(rows: list[FileDensity], policy: Policy) -> list[Violation]:
    """Violations, in file order. A density equal to the limit passes; anything above fails."""
    violations = []
    for r in rows:
        if is_critical(r.file, policy) and r.density_ai > policy.max_ai_density_critical_paths:
            violations.append(Violation(
                r.file, f"AI density {r.density_ai:.2f}/KLOC > {policy.max_ai_density_critical_paths:g} "
                        f"({r.ai_findings} finding(s) in {r.ai_lines} AI line(s))", r.density_ai))
        if policy.fail_on_unknown_origin and r.unknown_lines:
            violations.append(Violation(r.file, f"{r.unknown_lines} line(s) of unknown origin", r.density_ai))
    return violations
