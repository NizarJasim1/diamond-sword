"""The REAL runners that connect Diamond Sword to IOLITE and ONYX.

These are the glue the bridges always needed: ``IoliteBridge``/``OnyxBridge`` take a ``runner``
callable, and until now only a test fake was ever supplied. Here are the production runners.

They can't execute inside this sandbox (IOLITE/ONYX are not installed and there is no network),
so both are built around an INJECTED seam that the test suite drives with a fake, and that is the
real process/module on your machine:

- :func:`iolite_runner` shells out to the IOLITE CLI over the captured HAR(s) and loads the
  ONYX-ready ``spec.json`` IOLITE emits. The exact command and how the spec is read are both
  injectable, because IOLITE's flags live in its repo, not here — the default is the documented
  ``python3 -m iolite hook <har...> --out <spec>`` shape, and you override ``build_cmd`` once if
  your IOLITE differs. Any non-zero exit (with its stderr) or missing/invalid spec fails LOUD.
- :func:`onyx_runner` calls your ONYX link module (``onyx_link`` with ``verify_spec``/``scan``).
  ONYX alone judges; this only hands it the spec and returns its findings list, failing LOUD if
  the module lacks the functions or returns the wrong type.

Standard library only.
"""

from __future__ import annotations

import json
import os
import subprocess
from typing import Any, Callable, Sequence

__all__ = ["RunnerError", "iolite_runner", "onyx_runner"]


class RunnerError(RuntimeError):
    """Raised when a sibling tool fails to run or returns something unusable."""


def _default_iolite_cmd(python_exe: str, module: str, mode: str, spec_path: str) -> Callable[[Sequence[str]], list[str]]:
    def build(har_paths: Sequence[str]) -> list[str]:
        return [python_exe, "-m", module, mode, *har_paths, "--out", spec_path]
    return build


def iolite_runner(
    spec_path: str = "spec.json",
    *,
    python_exe: str = "python3",
    module: str = "iolite",
    mode: str = "hook",
    workdir: str | None = None,
    timeout: float = 600.0,
    build_cmd: Callable[[Sequence[str]], list[str]] | None = None,
    read_spec: Callable[[str], dict[str, Any]] | None = None,
    run: Callable[..., Any] = subprocess.run,
) -> Callable[[tuple[str, ...]], dict[str, Any]]:
    """Return a runner ``(har_paths) -> spec dict`` suitable for ``IoliteBridge``.

    ``run`` is injected (defaults to :func:`subprocess.run`) so tests drive a fake; ``build_cmd``
    and ``read_spec`` let you match your IOLITE's exact CLI without touching this file.
    """
    make_cmd = build_cmd or _default_iolite_cmd(python_exe, module, mode, spec_path)

    def _read(path: str) -> dict[str, Any]:
        if read_spec is not None:
            spec = read_spec(path)
        else:
            if not os.path.exists(path):
                raise RunnerError(f"IOLITE finished but no spec at {path!r}")
            with open(path, encoding="utf-8") as fh:
                spec = json.load(fh)
        if not isinstance(spec, dict):
            raise RunnerError("IOLITE spec must be a JSON object")
        return spec

    def runner(har_paths: tuple[str, ...]) -> dict[str, Any]:
        if not har_paths:
            raise RunnerError("IOLITE runner needs at least one HAR path")
        cmd = make_cmd(list(har_paths))
        try:
            proc = run(cmd, cwd=workdir, capture_output=True, text=True, timeout=timeout)
        except FileNotFoundError as exc:
            raise RunnerError(f"IOLITE not found: {cmd[0]!r} (install it / fix python_exe)") from exc
        except subprocess.TimeoutExpired as exc:
            raise RunnerError(f"IOLITE timed out after {timeout}s") from exc
        if getattr(proc, "returncode", 1) != 0:
            tail = (getattr(proc, "stderr", "") or "")[-800:]
            raise RunnerError(f"IOLITE exited {proc.returncode}: {tail}")
        return _read(spec_path)

    return runner


def onyx_runner(
    onyx_link: Any,
    *,
    verify_attr: str = "verify_spec",
    scan_attr: str = "scan",
) -> Callable[[dict[str, Any]], list[dict[str, Any]]]:
    """Return a runner ``(spec) -> findings list`` suitable for ``OnyxBridge``.

    ``onyx_link`` is your imported ONYX link module/object. If it exposes ``verify_spec`` it is
    called first (ONYX's own zero-FP gate); ``scan`` must exist and return a list of findings.
    """
    scan = getattr(onyx_link, scan_attr, None)
    if not callable(scan):
        raise RunnerError(f"ONYX link has no callable {scan_attr!r}")
    verify = getattr(onyx_link, verify_attr, None)

    def runner(spec: dict[str, Any]) -> list[dict[str, Any]]:
        if callable(verify):
            verify(spec)  # ONYX validates the spec on its own terms; it may raise — let it.
        findings = scan(spec)
        if not isinstance(findings, list):
            raise RunnerError(f"ONYX {scan_attr!r} must return a list, got {type(findings).__name__}")
        return findings

    return runner
