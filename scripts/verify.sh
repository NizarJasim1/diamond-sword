#!/usr/bin/env bash
# Diamond Sword verification kit. Run from the project root: bash scripts/verify.sh
set -u
root="$(cd "$(dirname "$0")/.." && pwd)"; cd "$root"
fail=0

echo "== byte-compile =="
python3 -m py_compile $(find diamond_sword tests -name '*.py') || fail=1

echo "== unit tests (stdlib) =="
python3 -m unittest discover -s tests -t . -q || fail=1

echo "== mutation (scope core) =="
for spec in tests/mutants/scope_mutants.json tests/mutants/roe_mutants.json tests/mutants/util_ledger_mutants.json tests/mutants/coverage_mutants.json tests/mutants/coverage2_mutants.json tests/mutants/heal_mutants.json tests/mutants/pipeline_mutants.json tests/mutants/capture_mutants.json tests/mutants/pipeline2_mutants.json; do
  [ -f "$spec" ] || continue
  echo "-- $spec"
  python3 scripts/apex_mutate.py . "$spec" -- \
    python3 -m unittest discover -s tests -t . -q || fail=1
done

echo "== static gates =="
if command -v ruff >/dev/null 2>&1 && command -v mypy >/dev/null 2>&1; then
  ruff check diamond_sword tests || fail=1
  mypy || fail=1
else
  echo "   ruff/mypy not installed; skipping (pip install ruff mypy)"
fi

[ "$fail" = 0 ] && echo "VERIFY: OK" || { echo "VERIFY: FAIL"; exit 1; }
