"""Diamond Sword command line: init, crawl, pipe, resume, report, verify.

- init/verify/report run offline anywhere.
- crawl: standalone read-only crawl (urllib, GET, scope-gated, paced) with a signed audit ledger.
- pipe: the full end-to-end run (crawl per principal -> HAR -> IOLITE -> ONYX -> report), wiring the
  real legal gates and the sibling tools. On large SPAs use the Playwright/
  mitmproxy backend on your machine (see RUNBOOK); the built-in urllib backend covers server-
  rendered pages and direct API endpoints and always writes a faithful multi-principal HAR.
- resume: rebuild crawl progress from the coverage ledger (nothing lost) and optionally continue.
"""
from __future__ import annotations
import argparse
import json
import os
import sys
import time
from collections.abc import Callable
from typing import Any

from .capture.har_model import HarEntry
from .coverage.crawler import Crawler, FetchResult
from .coverage.template_engine import TemplateMap
from .heal.coverage_ledger import rebuild
from .heal.pacer import Pacer
from .legal.audit_ledger import AuditLedger, verify as audit_verify
from .legal.scope_guard import ScopeGuard
from .legal.scope_parser import load_engagement
from .pipeline.report import build_report, to_markdown
from .pipeline.run import run_pipe
from .pipeline.runners import RunnerError, iolite_runner, onyx_runner

__all__ = ["main"]

_BASE_UA = {"User-Agent": "DiamondSword/1.1 (authorized testing)"}


def _load_json(path: str) -> Any:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def _urllib_backend(pacer: Pacer | None, timeout: float = 10.0) -> Callable[[str], FetchResult]:
    import urllib.request
    def fetch(url: str) -> FetchResult:
        if pacer is not None:
            time.sleep(pacer.next_delay())
        req = urllib.request.Request(url, headers=dict(_BASE_UA))
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 (scheme gated by ScopeGuard)
                html = resp.read().decode("utf-8", "replace")
                if pacer is not None:
                    pacer.on_success()
                return FetchResult(getattr(resp, "status", 200), html, resp.geturl())
        except Exception:
            return FetchResult(0, "", url)
    return fetch


# -- pipe/resume helpers ----------------------------------------------------------------

def _parse_principals(specs: list[str] | None) -> tuple[list[str], dict[str, dict[str, str]]]:
    """``["A=hdrs.json", "anon"]`` -> (names, {name: header dict}). Default: a single anon principal."""
    if not specs:
        return ["anon"], {}
    names: list[str] = []
    headers: dict[str, dict[str, str]] = {}
    for spec in specs:
        name, _, hpath = spec.partition("=")
        name = name.strip() or "anon"
        names.append(name)
        if hpath:
            loaded = _load_json(hpath)
            headers[name] = loaded if isinstance(loaded, dict) else {}
    return names, headers


def _import_onyx_link(path: str) -> Any:
    import importlib.util
    spec = importlib.util.spec_from_file_location("onyx_link", path)
    if spec is None or spec.loader is None:
        raise RunnerError(f"cannot import onyx_link from {path!r}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _recording_fetch_factory(headers_by_principal: dict[str, dict[str, str]], rps: float,
                             timeout: float = 10.0) -> Callable[..., Any]:
    """Build a per-principal recording urllib fetch: scope-gated GET, paced, appends a HAR entry."""
    import urllib.request

    def make_fetch(principal: str, guard: ScopeGuard, har: Any) -> Callable[[str], FetchResult | None]:
        headers = {**_BASE_UA, **headers_by_principal.get(principal, {})}
        pacer = Pacer(max_rps=rps)

        def fetch(url: str) -> FetchResult | None:
            if not guard.allowed(url):      # defense-in-depth; the crawler also checks
                return None
            time.sleep(pacer.next_delay())
            req = urllib.request.Request(url, headers=headers)
            try:
                with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 (scheme gated)
                    body = resp.read().decode("utf-8", "replace")
                    status = getattr(resp, "status", 200)
                    resp_headers = {k: v for k, v in resp.getheaders()}
                    pacer.on_success()
                    har.add(HarEntry(principal, "GET", url, status, req_headers=headers,
                                     resp_headers=resp_headers, resp_body=body))
                    return FetchResult(status, body, resp.geturl())
            except Exception:
                return FetchResult(0, "", url)
        return fetch

    return make_fetch


# -- commands ---------------------------------------------------------------------------

def _cmd_init(args: argparse.Namespace) -> int:
    eng = load_engagement(_load_json(args.engagement))
    print(f"program={eng.program} platform={eng.platform} "
          f"in={len(eng.network_in_scope)} out={len(eng.network_out_scope)} "
          f"out_classes={len(eng.out_classes)}")
    return 0


def _cmd_verify(args: argparse.Namespace) -> int:
    res = audit_verify(args.ledger)
    print(f"ok={res.ok} count={res.count} trailing_incomplete={res.trailing_incomplete} "
          f"broken_at={res.broken_at} reason={res.reason}")
    return 0 if res.ok else 1


def _cmd_report(args: argparse.Namespace) -> int:
    findings = _load_json(args.findings)
    report = build_report(findings if isinstance(findings, list) else findings.get("findings", []),
                          args.program)
    print(to_markdown(report))
    return 0


def _cmd_crawl(args: argparse.Namespace) -> int:
    eng = load_engagement(_load_json(args.engagement))
    ledger = AuditLedger(args.audit) if args.audit else None
    guard = ScopeGuard(eng, ledger.decision_sink if ledger else None)
    pacer = Pacer(max_rps=args.rps)
    crawler = Crawler(_urllib_backend(pacer), guard.allowed,
                      template_map=TemplateMap(), max_pages=args.max_pages)
    res = crawler.crawl(start=args.start)
    print(f"pages={len(res.pages)} templates={len(res.templates)} traps={len(res.traps)}")
    for t in res.templates:
        print(" T", t)
    return 0


def _cmd_pipe(args: argparse.Namespace) -> int:
    eng = load_engagement(_load_json(args.engagement))
    principals, headers = _parse_principals(args.principal)
    iolite_run = onyx_run = None
    if args.onyx_link:
        onyx_run = onyx_runner(_import_onyx_link(args.onyx_link))
        iolite_run = iolite_runner(spec_path=args.spec, module=args.iolite_module,
                                   mode=args.iolite_mode, workdir=args.har_dir)
    make_fetch = _recording_fetch_factory(headers, args.rps)
    res = run_pipe(eng, principals, make_fetch, start=args.start,
                   iolite_run=iolite_run, onyx_run=onyx_run,
                   audit_path=args.audit or None, coverage_path=args.coverage or None,
                   har_dir=args.har_dir, max_pages=args.max_pages)
    print(f"principals={principals} har={[os.path.basename(p) for p in res.har_paths]} "
          f"judged={res.judged} findings={len(res.findings)}")
    if res.report is not None:
        if args.out:
            with open(args.out, "w", encoding="utf-8") as fh:
                fh.write(to_markdown(res.report))
            print(f"report -> {args.out}")
        else:
            print(to_markdown(res.report))
    else:
        print("HARs written. Wire --onyx-link (and IOLITE) to judge; "
              "for SPA giants use the Playwright/mitmproxy backend (RUNBOOK).")
    return 0


def _cmd_explore(args: argparse.Namespace) -> int:
    """Interactive run: drive a logged-in app control-by-control (Playwright) and capture HAR.

    --principal NAME=storage.json gives each principal its saved Playwright storage_state (log in
    by hand once with `playwright codegen` or a saved context). Needs Playwright installed locally.
    """
    from .interact.direction import Direction
    from .pipeline.explore_run import playwright_make_driver, run_explore

    eng = load_engagement(_load_json(args.engagement))
    principals, storage = _parse_principals(args.principal)
    direction = Direction.from_doc(_load_json(args.playbook)) if args.playbook else None
    approver = None
    if args.yes:
        from .legal.consent_gate import AutoApprover
        approver = AutoApprover(True)

    try:
        from playwright.sync_api import sync_playwright
    except Exception:
        print("Playwright is required for `explore`. Install it on your machine:\n"
              "  pip install playwright && python -m playwright install chromium\n"
              "Then log in once per principal and save storage_state (see docs/ar/INTERACTION.md).")
        return 2

    iolite_run = onyx_run = None
    if args.onyx_link:
        onyx_run = onyx_runner(_import_onyx_link(args.onyx_link))
        iolite_run = iolite_runner(spec_path=args.spec, module=args.iolite_module,
                                   mode=args.iolite_mode, workdir=args.har_dir)

    storage_paths = {name: (storage.get(name) or "") for name in principals}
    with sync_playwright() as pw:  # pragma: no cover - live browser (L2)
        browser = pw.chromium.launch(headless=args.headless)
        make_driver = playwright_make_driver(
            browser, {k: v for k, v in storage_paths.items() if isinstance(v, str) and v})
        res = run_explore(eng, principals, make_driver, direction=direction,
                          approver=approver, start=args.start,
                          iolite_run=iolite_run, onyx_run=onyx_run,
                          audit_path=args.audit or None,
                          action_ledger_dir=args.ledger_dir or None, har_dir=args.har_dir)
        browser.close()

    for name, ex in res.explorations.items():
        print(f"[{name}] states={ex.states_seen} attempted={ex.actions_attempted} "
              f"performed={ex.actions_performed} traps={len(ex.traps)} "
              f"questions={len(ex.open_questions)} stopped={ex.stopped or '-'}")
    print(f"har={[os.path.basename(p) for p in res.har_paths]} judged={res.judged} "
          f"findings={len(res.findings)}")
    if res.report is not None:
        if args.out:
            with open(args.out, "w", encoding="utf-8") as fh:
                fh.write(to_markdown(res.report))
            print(f"report -> {args.out}")
        else:
            print(to_markdown(res.report))
    return 0


def _cmd_resume(args: argparse.Namespace) -> int:
    state = rebuild(args.coverage)
    pending = sorted(state.pending_frontier)
    print(f"events={state.events} visited={len(state.visited)} captured={sorted(state.principals)} "
          f"pending={len(pending)} open_questions={len(state.open_questions)} "
          f"trailing_incomplete={state.trailing_incomplete}")
    if args.engagement and pending:
        eng = load_engagement(_load_json(args.engagement))
        principals, headers = _parse_principals(args.principal)
        make_fetch = _recording_fetch_factory(headers, args.rps)
        res = run_pipe(eng, principals, make_fetch, seeds=pending,
                       audit_path=args.audit or None, coverage_path=args.coverage,
                       har_dir=args.har_dir, max_pages=args.max_pages)
        print(f"resumed from {len(pending)} pending; har={[os.path.basename(p) for p in res.har_paths]}")
    else:
        for u in pending[:args.show]:
            print(" P", u)
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="diamond_sword", description="legal multi-principal authz crawler")
    sub = p.add_subparsers(dest="cmd", required=True)

    pi = sub.add_parser("init"); pi.add_argument("engagement"); pi.set_defaults(fn=_cmd_init)
    pv = sub.add_parser("verify"); pv.add_argument("ledger"); pv.set_defaults(fn=_cmd_verify)
    pr = sub.add_parser("report"); pr.add_argument("findings"); pr.add_argument("--program", default="")
    pr.set_defaults(fn=_cmd_report)

    pc = sub.add_parser("crawl")
    pc.add_argument("engagement"); pc.add_argument("--start", required=True)
    pc.add_argument("--audit", default=""); pc.add_argument("--rps", type=float, default=1.0)
    pc.add_argument("--max-pages", dest="max_pages", type=int, default=500)
    pc.set_defaults(fn=_cmd_crawl)

    pp = sub.add_parser("pipe")
    pp.add_argument("engagement"); pp.add_argument("--start", required=True)
    pp.add_argument("--principal", action="append", help="NAME or NAME=headers.json (repeatable)")
    pp.add_argument("--audit", default=""); pp.add_argument("--coverage", default="")
    pp.add_argument("--out", default=""); pp.add_argument("--rps", type=float, default=1.0)
    pp.add_argument("--max-pages", dest="max_pages", type=int, default=500)
    pp.add_argument("--har-dir", dest="har_dir", default=".")
    pp.add_argument("--spec", default="spec.json")
    pp.add_argument("--iolite-module", dest="iolite_module", default="iolite")
    pp.add_argument("--iolite-mode", dest="iolite_mode", default="hook")
    pp.add_argument("--onyx-link", dest="onyx_link", default="", help="path to onyx_link.py (enables judging)")
    pp.set_defaults(fn=_cmd_pipe)

    pe = sub.add_parser("explore")
    pe.add_argument("engagement"); pe.add_argument("--start", default="")
    pe.add_argument("--playbook", default="", help="playbook.json with an interaction block (flows/priority/avoid/seeds)")
    pe.add_argument("--principal", action="append", help="NAME or NAME=storage_state.json (repeatable)")
    pe.add_argument("--yes", action="store_true", help="auto-approve CONSENT mutations (destructive still denied)")
    pe.add_argument("--headless", action="store_true")
    pe.add_argument("--audit", default=""); pe.add_argument("--ledger-dir", dest="ledger_dir", default="")
    pe.add_argument("--har-dir", dest="har_dir", default="."); pe.add_argument("--out", default="")
    pe.add_argument("--spec", default="spec.json")
    pe.add_argument("--iolite-module", dest="iolite_module", default="iolite")
    pe.add_argument("--iolite-mode", dest="iolite_mode", default="hook")
    pe.add_argument("--onyx-link", dest="onyx_link", default="")
    pe.set_defaults(fn=_cmd_explore)

    pre = sub.add_parser("resume")
    pre.add_argument("--coverage", required=True)
    pre.add_argument("--engagement", default="")
    pre.add_argument("--principal", action="append")
    pre.add_argument("--audit", default=""); pre.add_argument("--rps", type=float, default=1.0)
    pre.add_argument("--max-pages", dest="max_pages", type=int, default=500)
    pre.add_argument("--har-dir", dest="har_dir", default=".")
    pre.add_argument("--show", type=int, default=20)
    pre.set_defaults(fn=_cmd_resume)

    args = p.parse_args(argv)
    return int(args.fn(args))


if __name__ == "__main__":
    sys.exit(main())
