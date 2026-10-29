#!/usr/bin/env python3
"""APEX mutation runner: proves the tests can catch real bugs.
Usage: apex_mutate.py <project_dir> <mutants.json> -- <test command ...>
mutants.json: [{"file": "rel/path", "find": "exact text", "replace": "buggy text", "note": "why"}]
Each mutant is applied alone to a fresh temp copy and the test command runs there.
CAUGHT = tests failed (good). SURVIVED = tests passed with the bug (weak tests).
Exit code: 0 all caught, 1 some survived, 2 baseline failing or invalid mutants. Stdlib only."""
import json
import os
import shutil
import subprocess
import sys
import tempfile

TIMEOUT = int(os.environ.get("APEX_TIMEOUT", "120"))


def run(cwd, cmd):
    shell = len(cmd) == 1
    try:
        res = subprocess.run(cmd[0] if shell else cmd, cwd=cwd, shell=shell,
                             capture_output=True, text=True, timeout=TIMEOUT)
        return res.returncode, (res.stdout + res.stderr)[-600:]
    except subprocess.TimeoutExpired:
        return "timeout", ""


def copy(proj, dst):
    shutil.copytree(proj, dst, symlinks=True, ignore=shutil.ignore_patterns(".git", "__pycache__"))


def main():
    if "--" not in sys.argv or sys.argv.index("--") != 3:
        sys.exit(__doc__)
    proj, spec = sys.argv[1], sys.argv[2]
    cmd = sys.argv[4:]
    with open(spec, encoding="utf-8") as fh:
        mutants = json.load(fh)
    with tempfile.TemporaryDirectory() as tmp:
        base = os.path.join(tmp, "base")
        copy(proj, base)
        code, tail = run(base, cmd)
        if code != 0:
            print(f"BASELINE FAILS (exit {code}); fix the code or tests before mutation testing.\n{tail}")
            sys.exit(2)
    caught = survived = invalid = 0
    for i, m in enumerate(mutants, 1):
        label = f"#{i} {m['file']}: {m.get('note', '')}".rstrip(": ")
        path = os.path.join(proj, m["file"])
        try:
            with open(path, encoding="utf-8") as fh:
                count = fh.read().count(m["find"])
        except OSError:
            count = -1
        if count != 1:
            invalid += 1
            print(f"[INVALID]  {label}  (find text occurs {count if count >= 0 else 'n/a: file missing'} times; must be exactly 1)")
            continue
        with tempfile.TemporaryDirectory() as tmp:
            dst = os.path.join(tmp, "p")
            copy(proj, dst)
            target = os.path.join(dst, m["file"])
            with open(target, encoding="utf-8") as fh:
                text = fh.read()
            with open(target, "w", encoding="utf-8") as fh:
                fh.write(text.replace(m["find"], m["replace"], 1))
            code, _ = run(dst, cmd)
        if code == 0:
            survived += 1
            print(f"[SURVIVED] {label}  <- tests passed with this bug: add a test that fails on it")
        else:
            caught += 1
            print(f"[CAUGHT]   {label}  (exit {code})")
    valid = caught + survived
    print(f"Mutation score: {caught}/{valid} caught" + (f", {invalid} invalid" if invalid else ""))
    sys.exit(2 if invalid else (1 if survived else 0))


if __name__ == "__main__":
    main()
