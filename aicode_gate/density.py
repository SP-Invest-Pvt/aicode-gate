"""Join SARIF findings with line attribution and compute findings per 1,000 lines by origin."""
from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass
from pathlib import Path
from urllib.parse import unquote, urlparse

from . import GateError
from .attribution import FileAttribution


@dataclass(frozen=True)
class SarifFinding:
    file: str
    line: int
    rule_id: str


@dataclass
class FileDensity:
    file: str
    total_lines: int
    ai_lines: int
    human_lines: int
    ai_findings: int
    human_findings: int
    density_ai: float
    density_human: float
    unknown_lines: int

    def to_dict(self) -> dict:
        return asdict(self)


def density(findings: int, lines: int) -> float:
    """Findings per 1,000 lines. Zero lines gives 0.0 rather than a division error."""
    if lines <= 0:
        return 0.0
    return findings * 1000 / lines


def _normalise_uri(uri: str, repo_root: Path) -> str:
    if uri.startswith("file:"):
        uri = unquote(urlparse(uri).path)
        if os.name == "nt" and len(uri) > 2 and uri[0] == "/" and uri[2] == ":":
            uri = uri[1:]
    p = Path(uri)
    if p.is_absolute():
        try:
            p = p.resolve().relative_to(repo_root.resolve())
        except ValueError:
            return p.as_posix()
    return p.as_posix().removeprefix("./")


def load_sarif(path: str | Path, repo_root: str | Path = ".") -> list[SarifFinding]:
    """Findings from runs[].results[] with repository-relative paths."""
    try:
        doc = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    except FileNotFoundError:
        raise GateError(f"file not found: {path}") from None
    except json.JSONDecodeError as e:
        raise GateError(f"{path}: not valid JSON ({e.msg} at line {e.lineno})") from None
    if not isinstance(doc, dict) or not isinstance(doc.get("runs"), list):
        raise GateError(f"{path}: not a SARIF log (no 'runs' array)")
    root = Path(repo_root)
    out = []
    for run in doc["runs"]:
        for r in (run or {}).get("results") or []:
            loc = ((r.get("locations") or [{}])[0] or {}).get("physicalLocation") or {}
            uri = (loc.get("artifactLocation") or {}).get("uri")
            if not uri:
                continue
            try:
                line = int((loc.get("region") or {}).get("startLine") or 0)
            except (TypeError, ValueError):
                raise GateError(f"{path}: non-numeric startLine for {r.get('ruleId')}") from None
            out.append(SarifFinding(_normalise_uri(uri, root), line, r.get("ruleId") or "unknown-rule"))
    return out


def file_densities(attribution: dict[str, FileAttribution], findings: list[SarifFinding]) -> list[FileDensity]:
    """One row per attributed file. A finding counts as AI when its line came from an AI commit."""
    counts: dict[str, list[int]] = {}
    for f in findings:
        fa = attribution.get(f.file)
        if fa is None:
            continue
        c = counts.setdefault(f.file, [0, 0])
        c[0 if fa.origin_of(f.line) == "ai" else 1] += 1
    rows = []
    for path, fa in sorted(attribution.items()):
        ai_f, human_f = counts.get(path, [0, 0])
        rows.append(FileDensity(path, fa.total, fa.ai_lines, fa.human_lines, ai_f, human_f,
                                density(ai_f, fa.ai_lines), density(human_f, fa.human_lines), fa.unknown_lines))
    return rows
