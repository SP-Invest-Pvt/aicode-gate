"""Command line.

  python -m aicode_gate attribute --repo . [--format json]
  python -m aicode_gate check --repo . --sarif findings.sarif --policy policy.yaml [--format json]

Exit codes: 0 success / gate passed, 1 policy violated, 2 usage, configuration or git error.
Logs go to stderr; tables and JSON go to stdout.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import GateError, __version__
from .attribution import attribute, load_attribution_config
from .density import file_densities, load_sarif
from .gate import evaluate, is_critical, load_policy


def _log(msg: str) -> None:
    sys.stdout.flush()  # keep results and log lines in order when both go to one terminal or pipe
    print(f"aicode-gate: {msg}", file=sys.stderr)


def _attribution_cfg(a):
    path = a.attribution or (Path(a.repo) / "attribution.yaml")
    return load_attribution_config(path if a.attribution or Path(path).exists() else None)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="aicode-gate",
                                description="Attribute code to AI or human commits and gate on AI-code vulnerability density.")
    p.add_argument("--version", action="version", version=f"aicode-gate {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    def common(sp):
        sp.add_argument("--repo", default=".", help="git repository (default: .)")
        sp.add_argument("--attribution", metavar="YAML",
                        help="attribution rules (default: <repo>/attribution.yaml if present, else built-in)")
        sp.add_argument("--format", choices=["table", "json"], default="table")
        sp.add_argument("--ignore-whitespace", action="store_true",
                        help="blame with -w so re-indenting a line does not change its author")

    at = sub.add_parser("attribute", help="per-file AI line counts and ratio")
    common(at)
    at.add_argument("--path", action="append", metavar="PREFIX", help="only files under this prefix (repeatable)")

    ck = sub.add_parser("check", help="gate on AI-code vulnerability density in critical paths")
    common(ck)
    ck.add_argument("--sarif", required=True, help="SARIF findings for the same commit")
    ck.add_argument("--policy", required=True, metavar="YAML", help="gate policy")
    return p


def cmd_attribute(a) -> int:
    rows = attribute(a.repo, _attribution_cfg(a), prefixes=a.path, ignore_whitespace=a.ignore_whitespace)
    if a.format == "json":
        print(json.dumps([{"file": f.path, "total": f.total, "ai_lines": f.ai_lines, "ai_ratio": round(f.ai_ratio, 4)}
                          for f in rows.values()], indent=2))
    else:
        width = max([len("file")] + [len(p) for p in rows])
        print(f"{'file':<{width}}  {'total':>6}  {'ai_lines':>8}  {'ai_ratio':>8}")
        for f in rows.values():
            print(f"{f.path:<{width}}  {f.total:>6}  {f.ai_lines:>8}  {f.ai_ratio:>8.1%}")
    total = sum(f.total for f in rows.values())
    ai = sum(f.ai_lines for f in rows.values())
    _log(f"{len(rows)} file(s), {ai}/{total} line(s) AI-attributed ({ai / total:.1%})" if total
         else "no tracked text files")
    return 0


def cmd_check(a) -> int:
    policy = load_policy(a.policy)
    findings = load_sarif(a.sarif, a.repo)
    attributed = attribute(a.repo, _attribution_cfg(a), prefixes=list(policy.critical_paths),
                           ignore_whitespace=a.ignore_whitespace)
    rows = file_densities(attributed, findings)
    violations = evaluate(rows, policy)
    critical_rows = [r for r in rows if is_critical(r.file, policy)]
    if a.format == "json":
        print(json.dumps({"passed": not violations, "policy": {
            "max_ai_density_critical_paths": policy.max_ai_density_critical_paths,
            "critical_paths": list(policy.critical_paths),
            "fail_on_unknown_origin": policy.fail_on_unknown_origin},
            "files": [r.to_dict() for r in critical_rows],
            "violations": [v.to_dict() for v in violations]}, indent=2))
    else:
        width = max([len("file")] + [len(r.file) for r in critical_rows])
        print(f"{'file':<{width}}  {'ai_lines':>8}  {'ai_find':>7}  {'ai/KLOC':>8}  {'human/KLOC':>10}")
        for r in critical_rows:
            print(f"{r.file:<{width}}  {r.ai_lines:>8}  {r.ai_findings:>7}  {r.density_ai:>8.2f}  {r.density_human:>10.2f}")
        print()
        if violations:
            print(f"gate FAILED: {len(violations)} violation(s)")
            for v in violations:
                print(f"  {v.file}: {v.reason}")
        else:
            print("gate passed")
    _log(f"{len(findings)} finding(s), {len(critical_rows)} critical-path file(s) checked")
    return 1 if violations else 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    try:
        a = parser.parse_args(argv)
    except SystemExit as e:
        return int(e.code or 0)
    try:
        return cmd_attribute(a) if a.cmd == "attribute" else cmd_check(a)
    except GateError as e:
        _log(f"error: {e}")
        return 2
