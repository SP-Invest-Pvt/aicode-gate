# aicode-gate

See which lines of a repository came from AI-attributed commits, and fail the build when that code carries more SAST findings per 1,000 lines than your policy allows in the paths that matter.

[![ci](https://github.com/sp-kernel-stack/aicode-gate/actions/workflows/ci.yml/badge.svg)](../../actions/workflows/ci.yml)

## The problem

A growing share of code is written with AI assistants, and AI suggestions can carry security weaknesses like any other code. Teams that want to watch whether AI-written code is riskier than the rest cannot, because a diff does not say which lines an assistant wrote. SAST results do not say it either, so nobody can tell whether AI-written code in the authentication or payments module is getting worse.

The information often exists in git history anyway: bot authors such as `Copilot`, and trailers such as `Co-Authored-By: Claude` that coding agents add to commits. aicode-gate reads it, attributes every line through `git blame`, joins SAST findings to those lines, and applies a density ceiling to critical paths.

## How it works

1. **Classify commits.** `git log` gives author, subject and body for each commit. A commit is AI-attributed if the author (lowercased) is in `bots`, or the message contains any of `ai_markers` (case-insensitive), or `author_origin` maps the author to `ai`.
2. **Attribute lines.** `git blame --line-porcelain` maps each line to its commit, and so to `ai` or `human`. Uncommitted lines and lines from unclassified commits count as human.
3. **Join findings.** Each SARIF result is attached to the line it points at, which makes it an AI finding or a human finding.
4. **Compute density** per file: `density_ai = ai_findings / (ai_lines / 1000)`, and the same for human lines. A file with no AI lines has an AI density of 0.
5. **Gate.** Any file under `critical_paths` whose AI density is *above* `max_ai_density_critical_paths` is a violation. Equal to the limit passes. Optionally, `fail_on_unknown_origin` also fails files containing lines whose author is not in `author_origin`.

The specification this was built from matches markers against the commit subject (`%s`). aicode-gate reads the body as well, because `Co-Authored-By:` is a git trailer and trailers always sit in the body; matching the subject alone would miss the most common AI marker there is. Markers in the subject still match, and both cases are tested.

## Demo

`examples/build_demo_repo.sh` builds a three-commit repository: a human author writes session and refund code, the same author commits a password-reset module with a `Co-Authored-By: Claude` trailer, and a `Copilot` bot author extends the refund module. `examples/findings.sarif` is real [Bandit](https://github.com/PyCQA/bandit) 1.9.4 output for that repository. Nothing below is hand-edited.

```
$ examples/build_demo_repo.sh ../demo-repo
demo repository ready in ../demo-repo
$ (cd ../demo-repo && bandit -q -r src -f sarif -o ../aicode-gate/examples/findings.sarif)

$ python -m aicode_gate attribute --repo ../demo-repo --attribution examples/attribution.yaml
file                     total  ai_lines  ai_ratio
src/auth/reset.py           17        17    100.0%
src/auth/session.py         22         0      0.0%
src/payments/refund.py      18         6     33.3%
aicode-gate: 3 file(s), 23/57 line(s) AI-attributed (40.4%)

$ python -m aicode_gate check --repo ../demo-repo --sarif examples/findings.sarif --policy examples/policy.yaml --attribution examples/attribution.yaml
file                    ai_lines  ai_find   ai/KLOC  human/KLOC
src/auth/reset.py             17        4    235.29        0.00
src/auth/session.py            0        0      0.00        0.00
src/payments/refund.py         6        2    333.33        0.00

gate FAILED: 2 violation(s)
  src/auth/reset.py: AI density 235.29/KLOC > 5 (4 finding(s) in 17 AI line(s))
  src/payments/refund.py: AI density 333.33/KLOC > 5 (2 finding(s) in 6 AI line(s))
aicode-gate: 6 finding(s), 3 critical-path file(s) checked
$ echo $?
1
```

What Bandit found in the AI-attributed lines: a password-reset token built from `random.random()` and MD5, SQL assembled with an f-string and with `%`, and a `subprocess` call with `shell=True` and interpolated data. The human-written session module uses `secrets` and `hmac.compare_digest` and has no findings. Densities are large because the files are tiny; on a real code base the same arithmetic runs over thousands of lines.

## Install

Python 3.11 or newer and `git` on `PATH`. The only dependency is PyYAML.

```bash
git clone https://github.com/sp-kernel-stack/aicode-gate && cd aicode-gate
pip install -e ".[test]"
pytest
python -m aicode_gate --help
```

## Usage

```
python -m aicode_gate attribute --repo . [--attribution attribution.yaml] [--path PREFIX ...] [--ignore-whitespace] [--format table|json]
python -m aicode_gate check --repo . --sarif findings.sarif --policy policy.yaml [--attribution attribution.yaml] [--ignore-whitespace] [--format table|json]
```

`check` runs `git blame` only for files under `critical_paths`, so it stays fast on large repositories. Exit codes: `0` gate passed (or attribution printed), `1` policy violated, `2` usage, configuration or git error (for example a missing key in the policy, malformed SARIF, or a directory that is not a repository). Logs go to stderr; tables and JSON go to stdout.

### GitHub Action

```yaml
- uses: actions/checkout@v7
  with:
    fetch-depth: 0            # blame needs history
- run: bandit -r src -f sarif -o findings.sarif || true   # or any SARIF-producing scanner
- uses: sp-kernel-stack/aicode-gate@main
  with:
    sarif: findings.sarif
    policy: .github/aicode-gate.yaml
```

Inputs: `sarif` and `policy` (required), `attribution`, `repo` (default `.`) and `python-version` (default `3.12`). Inputs reach the shell through environment variables, never through inline expression expansion. This repository's CI runs the action against the demo repository and requires it to fail.

## Configuration

`attribution.yaml` (defaults shown; used from `<repo>/attribution.yaml` when present):

```yaml
bots: [claude, copilot, cursor]          # author names, compared lowercased
ai_markers: ["Co-Authored-By: Claude", "generated with", "AI-assisted"]   # substrings of the commit message
author_origin: {"sankalp": human}        # optional explicit map: author -> ai | human
```

`policy.yaml` (every key is required; a missing or unknown key exits 2):

```yaml
max_ai_density_critical_paths: 5.0       # findings per 1,000 AI lines; equal passes, above fails
critical_paths: ["src/auth/", "src/payments/"]
fail_on_unknown_origin: false            # true: also fail files with lines from unmapped authors
```

## Limitations

* **Attribution is a heuristic.** It sees only what commit metadata admits to. Code pasted from a chat window, suggestions accepted inline under a human's name, and squash merges that drop trailers all count as human. Treat the AI share as a lower bound.
* **Blame follows the last change.** A human who edits an AI-written line becomes its author. Pure re-indentation is handled by `--ignore-whitespace` (git blame `-w`), and formatting-only commits listed in the repository's `.git-blame-ignore-revs` are skipped automatically. Substantive edits still move the line to the editor.
* **Small numbers are noisy.** One finding in 17 AI lines is 58.8 per KLOC. Density is meaningful across a module or a quarter, not for a single small file, so set the ceiling with your own baseline in mind.
* **Findings count equally.** A low-severity note and a critical injection each add one. Filter the SARIF by severity before the gate if that matters for your policy.
* **Scanner coverage bounds everything.** A density of zero means the scanner found nothing, not that the code is safe.
* **Running it on this repository reports close to 100% AI.** Its commits carry `Co-Authored-By: Claude` trailers because it was written with an AI assistant, which is the kind of disclosure this tool depends on.

## Licence

MIT.
