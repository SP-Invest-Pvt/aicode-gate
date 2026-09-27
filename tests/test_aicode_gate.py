import json
import subprocess
from pathlib import Path

import pytest

from aicode_gate import GateError
from aicode_gate.attribution import (AttributionConfig, attribute, classify_commit, load_attribution_config)
from aicode_gate.cli import main
from aicode_gate.density import FileDensity, SarifFinding, density, file_densities, load_sarif
from aicode_gate.gate import Policy, evaluate, load_policy, parse_policy

from .conftest import git, write

FX = Path(__file__).parent / "fixtures"
CFG = load_attribution_config(None)


def run(capsys, *argv):
    code = main([str(a) for a in argv])
    out, err = capsys.readouterr()
    return code, out, err


def sarif(tmp_path, results):
    doc = {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "t"}}, "results": [
        {"ruleId": rule, "locations": [{"physicalLocation": {"artifactLocation": {"uri": f},
                                                             "region": {"startLine": line}}}]}
        for f, line, rule in results]}]}
    p = tmp_path / "findings.sarif"
    p.write_text(json.dumps(doc))
    return p


def row(ai_findings, ai_lines, file="src/auth/x.py", unknown=0):
    return FileDensity(file, ai_lines + 100, ai_lines, 100, ai_findings, 0,
                       density(ai_findings, ai_lines), 0.0, unknown)


# --- the four required tests -------------------------------------------------------------

def test_attribution_ratio(repo):
    rows = attribute(repo, CFG)
    got = {p: (fa.ai_lines, fa.total) for p, fa in rows.items()}
    assert got == {
        "src/auth/login.py": (6, 16),       # Co-Authored-By: Claude trailer
        "src/payments/pay.py": (4, 8),      # bot author "Copilot"
        "src/util.py": (5, 5),              # bot author "Copilot"
    }
    assert rows["src/auth/login.py"].ai_ratio == pytest.approx(0.375)
    login = rows["src/auth/login.py"]
    assert login.origin_of(10) == "human" and login.origin_of(11) == "ai"


def test_density_math():
    assert density(2, 400) == 5.0
    assert density(0, 400) == 0.0
    assert density(3, 0) == 0.0  # guarded: no lines means no density


def test_threshold_boundary():
    policy = Policy(5.0, ("src/auth/",), False)
    assert evaluate([row(2, 400)], policy) == []                 # exactly 5.0/KLOC passes
    failed = evaluate([row(2, 399)], policy)                     # 5.0125/KLOC fails
    assert len(failed) == 1 and failed[0].file == "src/auth/x.py"
    epsilon = Policy(5.0 - 1e-9, ("src/auth/",), False)
    assert len(evaluate([row(2, 400)], epsilon)) == 1           # threshold + epsilon


def test_bad_policy(tmp_path, capsys, repo):
    p = tmp_path / "policy.yaml"
    p.write_text("max_ai_density_critical_paths: 5.0\ncritical_paths: [src/auth/]\n")
    s = sarif(tmp_path, [])
    code, out, err = run(capsys, "check", "--repo", repo, "--sarif", s, "--policy", p)
    assert code == 2
    assert "missing key(s): fail_on_unknown_origin" in err
    assert out == ""


# --- attribution ------------------------------------------------------------------------

def test_marker_in_subject_and_case_insensitive():
    assert classify_commit("sankalp", "Generated with Claude Code", CFG) == ("ai", True)
    assert classify_commit("sankalp", "fix: typo\n\nai-assisted refactor", CFG) == ("ai", True)
    assert classify_commit("CURSOR", "wip", CFG) == ("ai", True)
    assert classify_commit("sankalp", "fix: typo", CFG) == ("human", False)


def test_author_origin_map():
    cfg = AttributionConfig(["claude"], ["AI-assisted"], {"sankalp": "human", "agent-7": "ai"})
    assert classify_commit("Sankalp", "fix", cfg) == ("human", True)
    assert classify_commit("agent-7", "fix", cfg) == ("ai", True)
    assert classify_commit("sankalp", "AI-assisted fix", cfg) == ("ai", True)  # markers still apply


def test_unknown_origin_lines(repo):
    cfg = AttributionConfig(["copilot"], ["co-authored-by: claude"], {})
    login = attribute(repo, cfg)["src/auth/login.py"]
    assert login.unknown_lines == 10  # human lines from an author not in author_origin
    mapped = AttributionConfig(["copilot"], ["co-authored-by: claude"], {"sankalp": "human"})
    assert attribute(repo, mapped)["src/auth/login.py"].unknown_lines == 0


def test_uncommitted_lines_count_as_human(repo):
    write(repo, "src/util.py", [f"bot_util_{i} = {i}" for i in range(1, 6)] + ["local_edit = 1"])
    util = attribute(repo, CFG)["src/util.py"]
    assert (util.ai_lines, util.total) == (5, 6)


def test_binary_files_skipped_and_prefix_filter(repo):
    (repo / "logo.bin").write_bytes(b"\x00\x01\x02")
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "chore: logo")
    assert "logo.bin" not in attribute(repo, CFG)
    assert set(attribute(repo, CFG, prefixes=["src/payments/"])) == {"src/payments/pay.py"}


@pytest.mark.parametrize("content, message", [
    ("bots: claude\n", "bots must be a list"),
    ("author_origin: {sankalp: robot}\n", "'ai' or 'human'"),
    ("colour: blue\n", "unknown key"),
    ("- a\n", "expected a mapping"),
    ("bots: [\n", "invalid YAML"),
])
def test_attribution_config_errors(tmp_path, content, message):
    p = tmp_path / "attribution.yaml"
    p.write_text(content)
    with pytest.raises(GateError, match=message):
        load_attribution_config(p)


def test_not_a_git_repo(tmp_path, capsys):
    code, _, err = run(capsys, "attribute", "--repo", tmp_path)
    assert code == 2 and "git log failed" in err and "not a git repository" in err


# --- density and SARIF ------------------------------------------------------------------

def test_findings_join_by_line_origin(repo, tmp_path):
    s = sarif(tmp_path, [("src/auth/login.py", 12, "sqli"), ("src/auth/login.py", 13, "xss"),
                         ("./src/auth/login.py", 2, "weak-hash"), ("src/other.py", 1, "ignored")])
    rows = {r.file: r for r in file_densities(attribute(repo, CFG), load_sarif(s, repo))}
    login = rows["src/auth/login.py"]
    assert (login.ai_findings, login.human_findings) == (2, 1)
    assert login.density_ai == pytest.approx(2 * 1000 / 6)
    assert login.density_human == pytest.approx(1 * 1000 / 10)


def test_absolute_file_uri_is_made_relative(repo, tmp_path):
    uri = (repo / "src" / "util.py").resolve().as_uri()
    findings = load_sarif(sarif(tmp_path, [(uri, 1, "r")]), repo)
    assert findings == [SarifFinding("src/util.py", 1, "r")]


def test_empty_and_malformed_sarif(tmp_path):
    assert load_sarif(sarif(tmp_path, [])) == []
    bad = tmp_path / "bad.sarif"
    bad.write_text('{"runs": [')
    with pytest.raises(GateError, match="not valid JSON"):
        load_sarif(bad)
    bad.write_text('{"version": "2.1.0"}')
    with pytest.raises(GateError, match="no 'runs' array"):
        load_sarif(bad)
    with pytest.raises(GateError, match="file not found"):
        load_sarif(tmp_path / "missing.sarif")


# --- policy -----------------------------------------------------------------------------

@pytest.mark.parametrize("doc, message", [
    ({"max_ai_density_critical_paths": -1, "critical_paths": ["a/"], "fail_on_unknown_origin": False}, ">= 0"),
    ({"max_ai_density_critical_paths": 5, "critical_paths": [], "fail_on_unknown_origin": False}, "non-empty list"),
    ({"max_ai_density_critical_paths": 5, "critical_paths": ["a/"], "fail_on_unknown_origin": "no"}, "true or false"),
    ({"max_ai_density_critical_paths": 5, "critical_paths": ["a/"], "fail_on_unknown_origin": False, "x": 1},
     "unknown key"),
    ("just a string", "expected a mapping"),
])
def test_policy_validation(doc, message):
    with pytest.raises(GateError, match=message):
        parse_policy(doc)


def test_policy_file_errors(tmp_path):
    with pytest.raises(GateError, match="file not found"):
        load_policy(tmp_path / "nope.yaml")
    p = tmp_path / "p.yaml"
    p.write_text("critical_paths: [\n")
    with pytest.raises(GateError, match="invalid YAML"):
        load_policy(p)


def test_fail_on_unknown_origin():
    policy = Policy(100.0, ("src/",), True)
    violations = evaluate([row(0, 10, unknown=3)], policy)
    assert [v.reason for v in violations] == ["3 line(s) of unknown origin"]


def test_non_critical_files_are_not_gated():
    assert evaluate([row(50, 10, file="docs/x.py")], Policy(1.0, ("src/auth/",), False)) == []


# --- CLI --------------------------------------------------------------------------------

def test_cli_attribute_table_and_json(repo, capsys):
    code, out, err = run(capsys, "attribute", "--repo", repo)
    assert code == 0 and "src/auth/login.py" in out and "37.5%" in out
    assert "15/29 line(s) AI-attributed" in err
    code, out, _ = run(capsys, "attribute", "--repo", repo, "--format", "json")
    assert {r["file"]: r["ai_ratio"] for r in json.loads(out)} == {
        "src/auth/login.py": 0.375, "src/payments/pay.py": 0.5, "src/util.py": 1.0}


def test_cli_check_pass_and_fail(repo, tmp_path, capsys):
    policy = tmp_path / "policy.yaml"
    policy.write_text("max_ai_density_critical_paths: 5.0\ncritical_paths: [src/auth/, src/payments/]\n"
                      "fail_on_unknown_origin: false\n")
    clean = sarif(tmp_path, [("src/auth/login.py", 1, "human-only")])
    code, out, _ = run(capsys, "check", "--repo", repo, "--sarif", clean, "--policy", policy)
    assert code == 0 and "gate passed" in out

    dirty = sarif(tmp_path, [("src/payments/pay.py", 6, "sqli")])  # a bot-written line
    code, out, _ = run(capsys, "check", "--repo", repo, "--sarif", dirty, "--policy", policy, "--format", "json")
    report = json.loads(out)
    assert code == 1 and report["passed"] is False
    assert report["violations"] == [{"file": "src/payments/pay.py", "density_ai": 250.0,
                                     "reason": "AI density 250.00/KLOC > 5 (1 finding(s) in 4 AI line(s))"}]


def test_cli_attribution_file_in_repo_is_used(repo, capsys):
    (repo / "attribution.yaml").write_text("bots: []\nai_markers: []\n")
    code, out, _ = run(capsys, "attribute", "--repo", repo, "--format", "json", "--path", "src/")
    assert code == 0 and all(r["ai_lines"] == 0 for r in json.loads(out))


def test_cli_help_and_usage(capsys):
    assert main(["--help"]) == 0
    assert "attribute" in capsys.readouterr().out
    assert main(["check", "--repo", "."]) == 2  # --sarif and --policy are required


def _reindent_util_as_human(repo):
    write(repo, "src/util.py", [f"    bot_util_{i} = {i}" for i in range(1, 6)])
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "style: indent util")


def test_reindenting_changes_author_by_default(repo):
    _reindent_util_as_human(repo)
    assert attribute(repo, CFG)["src/util.py"].ai_lines == 0


def test_ignore_whitespace_keeps_ai_origin(repo, capsys):
    _reindent_util_as_human(repo)
    assert attribute(repo, CFG, ignore_whitespace=True)["src/util.py"].ai_lines == 5
    code, out, _ = run(capsys, "attribute", "--repo", repo, "--ignore-whitespace", "--format", "json")
    assert code == 0 and {r["file"]: r["ai_lines"] for r in json.loads(out)}["src/util.py"] == 5


def test_blame_ignore_revs_file_is_honoured(repo):
    _reindent_util_as_human(repo)
    head = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"], capture_output=True, text=True,
                          check=True).stdout.strip()
    (repo / ".git-blame-ignore-revs").write_text(f"# formatting\n{head}\n")
    assert attribute(repo, CFG)["src/util.py"].ai_lines == 5
