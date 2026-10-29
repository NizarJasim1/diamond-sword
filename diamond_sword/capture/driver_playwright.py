"""Live browser driver (the real hand) \u2014 runs on YOUR machine, needs a real browser.

Implements :class:`diamond_sword.interact.explorer.DriverPort` over Playwright, and captures
EVERY request the page makes (navigations, XHR, fetch, GraphQL) into a multi-principal
:class:`HarLog` via a response listener \u2014 this is the "capture everything" half the explorer
relies on. For full fidelity (request/response bodies, non-browser traffic) also run mitmdump
with :class:`diamond_sword.capture.backend_mitmproxy.DiamondSwordAddon` as an upstream proxy and
merge the two HARs; the browser listener alone already covers the authz surface.

This module is import-safe without Playwright (all heavy imports are lazy) and is not unit-tested
(``pragma: no cover``) because it requires a live browser; its logic is deliberately thin \u2014 all the
decisions live in the deterministic, tested core (``interact/``). Standard library only at module
scope.

Typical use (sketch)::

    from playwright.sync_api import sync_playwright
    from diamond_sword.capture.driver_playwright import PlaywrightDriver
    from diamond_sword.interact.explorer import Explorer, ExploreConfig
    # ... build engagement, ScopeGuard, RoePolicy, ConsentGate, Direction ...
    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=False)
        ctx = browser.new_context(storage_state="A.storage.json")  # human logged in once
        page = ctx.new_page()
        driver = PlaywrightDriver(page, principal="A")
        Explorer(driver, guard, gate, "A", direction=direction,
                 config=ExploreConfig()).run(start="https://target/")
        driver.har.write("capture.A.har")
"""
from __future__ import annotations

from typing import Any, cast

from ..heal.invariant import StabilityTracker
from ..heal.locator_cascade import DomSnapshot, Element, Target
from ..heal.recovery_fsm import Signals
from ..interact.action import FILL, NAVIGATE, SELECT, StateView, UiAction
from ..util.hashing import sha256_hex
from .har_model import HarEntry, HarLog

__all__ = ["PlaywrightDriver", "SNAPSHOT_JS"]

# Extract interactive controls + a structural skeleton hash from the live DOM. Returns
# {"url", "hash", "elements":[{node_id, tag, role, test_id, label, text, href, input_type,
# ancestors[]}]}. Roles use ARIA where present, else a small implicit-role map.
SNAPSHOT_JS = r"""
() => {
  const IMPLICIT = {a:'link', button:'button', select:'combobox', textarea:'textbox',
                    summary:'button'};
  const inputRole = (el) => {
    const t = (el.getAttribute('type')||'text').toLowerCase();
    if (t==='checkbox') return 'checkbox';
    if (t==='radio') return 'radio';
    if (['submit','button','image','reset'].includes(t)) return 'button';
    return 'textbox';
  };
  const roleOf = (el) => {
    const r = el.getAttribute('role'); if (r) return r;
    const tag = el.tagName.toLowerCase();
    if (tag==='input') return inputRole(el);
    return IMPLICIT[tag] || null;
  };
  const labelOf = (el) => {
    return el.getAttribute('aria-label') || el.getAttribute('placeholder') ||
           (el.labels && el.labels[0] && el.labels[0].innerText) || null;
  };
  const visible = (el) => {
    const s = window.getComputedStyle(el);
    if (s.display==='none' || s.visibility==='hidden' || s.opacity==='0') return false;
    const r = el.getBoundingClientRect();
    return r.width>0 && r.height>0;
  };
  const anc = (el) => {
    const out = []; let p = el.parentElement; let depth = 0;
    while (p && depth<12) {
      const id = p.getAttribute('data-testid') || p.id; if (id) out.push(id);
      p = p.parentElement; depth++;
    }
    return out;
  };
  const SEL = 'a,button,input,select,textarea,summary,[role],[onclick],[tabindex]';
  const nodes = Array.from(document.querySelectorAll(SEL));
  const els = []; const skel = []; let i = 0;
  for (const el of nodes) {
    const role = roleOf(el);
    const tag = el.tagName.toLowerCase();
    const interactive = ['a','button','input','select','textarea'].includes(tag) ||
      ['button','link','menuitem','tab','checkbox','switch','radio','option','combobox',
       'textbox','searchbox'].includes(role||'');
    if (!interactive || !visible(el)) continue;
    skel.push(tag + ':' + (role||''));
    els.push({
      node_id: 'n'+(i++),
      tag,
      role: role,
      test_id: el.getAttribute('data-testid'),
      label: labelOf(el),
      text: (el.innerText||el.value||'').trim().slice(0,120) || null,
      href: el.getAttribute('href'),
      input_type: tag==='input' ? (el.getAttribute('type')||'text').toLowerCase() : null,
      ancestors: anc(el),
    });
  }
  return {url: location.href, hash: skel.sort().join('|'), elements: els};
}
"""


class PlaywrightDriver:  # pragma: no cover - requires a live browser (L2)
    """Thin DriverPort over a Playwright ``page``. Captures all traffic into ``self.har``."""

    def __init__(self, page: Any, principal: str = "A", har: HarLog | None = None,
                 stability_required: int = 3, settle_polls: int = 20,
                 settle_pause_ms: int = 150) -> None:
        self.page = page
        self.principal = principal
        self.har = har or HarLog()
        self._required = stability_required
        self._polls = settle_polls
        self._pause = settle_pause_ms
        self._last_status = 200
        self._wire_capture()

    # -- capture -----------------------------------------------------------------------

    def _wire_capture(self) -> None:
        def on_response(response: Any) -> None:
            try:
                req = response.request
                body = None
                ct = (response.headers or {}).get("content-type", "")
                if any(k in ct for k in ("json", "text", "xml", "javascript", "html", "form")):
                    try:
                        body = response.text()
                    except Exception:
                        body = None
                self.har.add(HarEntry(
                    principal=self.principal,
                    method=req.method,
                    url=req.url,
                    status=int(response.status),
                    req_headers=dict(req.headers or {}),
                    req_body=req.post_data,
                    resp_headers=dict(response.headers or {}),
                    resp_body=body,
                ))
                if req.resource_type == "document":
                    self._last_status = int(response.status)
            except Exception:
                return
        self.page.on("response", on_response)

    # -- settle + snapshot -------------------------------------------------------------

    def _raw_snapshot(self) -> dict[str, Any]:
        return cast(dict[str, Any], self.page.evaluate(SNAPSHOT_JS))

    def _view_from(self, data: dict[str, Any]) -> StateView:
        elements = tuple(
            Element(
                node_id=e["node_id"], tag=e["tag"], role=e.get("role"),
                test_id=e.get("test_id"), label=e.get("label"), text=e.get("text"),
                ancestors=tuple(e.get("ancestors") or ()),
                href=e.get("href"), input_type=e.get("input_type"),
            )
            for e in data.get("elements", [])
        )
        snap = DomSnapshot(url=data.get("url", ""), elements=elements)
        tree_hash = sha256_hex(data.get("hash", ""))
        waf = self._last_status in (403, 406, 429, 503)
        return StateView(snap, tree_hash, Signals(http_status=self._last_status, waf=waf))

    def snapshot(self) -> StateView:
        """Wait for the DOM to settle (``required`` identical structural hashes), then snapshot."""
        tracker = StabilityTracker(required=self._required)
        data = self._raw_snapshot()
        for _ in range(self._polls):
            if tracker.push(sha256_hex(data.get("hash", ""))):
                break
            self.page.wait_for_timeout(self._pause)
            data = self._raw_snapshot()
        return self._view_from(data)

    # -- perform -----------------------------------------------------------------------

    def _locator(self, t: Target) -> Any:
        page = self.page
        if t.test_id:
            return page.get_by_test_id(t.test_id)
        if t.role and t.text:
            return page.get_by_role(t.role, name=t.text, exact=True)
        if t.label:
            return page.get_by_label(t.label, exact=True)
        if t.text:
            return page.get_by_text(t.text, exact=True)
        if t.css:
            return page.locator(t.css)
        if t.role:
            return page.get_by_role(t.role)
        return page.locator(t.tag or "*")

    def perform(self, ui: UiAction) -> StateView:
        loc = self._locator(ui.target).first
        try:
            if ui.kind == FILL and ui.value is not None:
                loc.fill(ui.value)
            elif ui.kind == SELECT:
                loc.select_option(index=1)
            elif ui.kind == NAVIGATE and ui.url:
                self.page.goto(ui.url)
            else:  # CLICK / SUBMIT
                loc.click()
        except Exception:
            pass
        return self.snapshot()

    def goto(self, url: str) -> StateView:
        try:
            self.page.goto(url)
        except Exception:
            pass
        return self.snapshot()

    def dismiss_modal(self) -> StateView:
        try:
            self.page.keyboard.press("Escape")
        except Exception:
            pass
        return self.snapshot()
