"""A tiny deterministic SPA that implements the explorer's DriverPort, for tests.

Screens: /login -> /dashboard (links: Orders/Settings/Admin, buttons: Create [mutating],
Help [opens modal]) ; /orders (3 order links that collapse to one template) ;
/orders/{id} (Delete [destructive], Edit [mutating], Back) ; /settings (displayName fill,
notifications toggle, Update [mutating]) ; /admin (-> Users) requires auth, else redirects to
/login with 403. Every action appends a HAR entry so capture can be asserted. No AI, no network.
"""
from __future__ import annotations

from diamond_sword.capture.har_model import HarEntry, HarLog
from diamond_sword.heal.locator_cascade import DomSnapshot, Element
from diamond_sword.heal.recovery_fsm import Signals
from diamond_sword.interact.action import FILL, SELECT, StateView
from diamond_sword.legal.scope_parser import load_engagement
from diamond_sword.util.hashing import sha256_hex

ORIGIN = "https://app.test"

ENGAGEMENT = {
    "program": "fake", "platform": "local",
    "scope": {"in": [{"type": "web", "host": "app.test"}], "out": [], "out_classes": []},
    "roe": {"read_only": True},
}


def engagement():
    return load_engagement(ENGAGEMENT)


def _el(node_id: str, tag: str, **kw) -> Element:
    return Element(node_id, tag, **kw)


class FakeApp:
    def __init__(self, authenticated: bool = False, with_evil_link: bool = False,
                 rate_limit_at: int | None = None) -> None:
        self.url = "/login"
        self.auth = authenticated
        self.modal = False
        self.filled: dict[str, str] = {}
        self.toggled: set[str] = set()
        self.har = HarLog()
        self.dismiss_calls = 0
        self.with_evil = with_evil_link
        self._n = 0
        self._rl_at = rate_limit_at
        self._rl_fired = False

    # -- screens -----------------------------------------------------------------------

    def _elements(self) -> tuple[Element, ...]:
        if self.modal:
            return (_el("d", "div", role="dialog"),
                    _el("pn", "input", test_id="proj-name", input_type="text"),
                    _el("sv", "button", role="button", text="Save"))
        u = self.url
        if u == "/login":
            return (_el("em", "input", test_id="email", input_type="email"),
                    _el("pw", "input", test_id="password", input_type="password"),
                    _el("si", "button", role="button", text="Sign in"))
        if u == "/dashboard":
            base = [_el("lo", "a", role="link", text="Orders", href="/orders"),
                    _el("ls", "a", role="link", text="Settings", href="/settings"),
                    _el("la", "a", role="link", text="Admin", href="/admin"),
                    _el("cr", "button", role="button", text="Create"),
                    _el("hp", "button", role="button", text="Help")]
            if self.with_evil:
                base.append(_el("ev", "a", role="link", text="External", href="https://evil.test/x"))
            return tuple(base)
        if u == "/orders":
            return (_el("o1", "a", role="link", text="Order 1", href="/orders/1"),
                    _el("o2", "a", role="link", text="Order 2", href="/orders/2"),
                    _el("o3", "a", role="link", text="Order 3", href="/orders/3"))
        if u.startswith("/orders/"):
            return (_el("del", "button", role="button", text="Delete"),
                    _el("edt", "button", role="button", text="Edit"),
                    _el("bk", "a", role="link", text="Back", href="/orders"))
        if u == "/settings":
            return (_el("dn", "input", test_id="displayName", input_type="text"),
                    _el("nt", "input", test_id="notifications", input_type="checkbox"),
                    _el("up", "button", role="button", text="Update"))
        if u == "/admin":
            return (_el("us", "a", role="link", text="Users", href="/admin/users"),)
        if u == "/admin/users":
            return (_el("bk2", "a", role="link", text="Back", href="/admin"),)
        return ()

    def _signals(self) -> Signals:
        if self._rl_at is not None and self._n >= self._rl_at and not self._rl_fired:
            self._rl_fired = True
            return Signals(http_status=429)
        return Signals(http_status=200)

    def _view(self, status: int | None = None) -> StateView:
        snap = DomSnapshot(ORIGIN + self.url, self._elements())
        skel = "|".join(sorted(f"{e.tag}:{e.role or ''}" for e in snap.elements))
        sig = Signals(http_status=status) if status is not None else self._signals()
        th = sha256_hex(f"{self.url}|{skel}|{'1' if self.auth else '0'}|{'m' if self.modal else ''}")
        return StateView(snap, th, sig)

    def _log(self, method: str, url: str, status: int = 200) -> None:
        full = ORIGIN + url if url.startswith("/") else url
        self.har.add(HarEntry("A", method, full, status, resp_body="<x/>"))

    # -- DriverPort --------------------------------------------------------------------

    def snapshot(self) -> StateView:
        return self._view()

    def goto(self, url: str) -> StateView:
        self._n += 1
        path = url.replace(ORIGIN, "")
        if path == "/admin" and not self.auth:
            self.url = "/login"
            self._log("GET", "/admin", 403)
            return self._view(status=403)
        self.url = path
        self.modal = False
        self._log("GET", path, 200)
        return self._view()

    def perform(self, ui) -> StateView:
        self._n += 1
        if self._rl_at is not None and self._n >= self._rl_at and not self._rl_fired:
            self._rl_fired = True
            self._log("GET", self.url, 429)
            return self._view(status=429)

        k, t = ui.kind, ui.target
        if k == FILL:
            self.filled[t.test_id or t.text or "?"] = ui.value
            self._log("POST", self.url + "#fill", 200)
            return self._view()
        if k == SELECT:
            self._log("POST", self.url + "#select", 200)
            return self._view()

        label = t.text or t.label or t.test_id or ""
        if t.test_id == "notifications":
            self.toggled.add(label)
            self._log("POST", self.url + "#toggle", 200)
            return self._view()
        if label == "Sign in":
            if self.filled.get("email") and self.filled.get("password"):
                self.auth = True
                self.url = "/dashboard"
            self._log("POST", "/login", 200)
            return self._view()
        if label == "Create":
            self.modal = True
            self._log("POST", "/dashboard#create", 200)
            return self._view()
        if label == "Help":
            self.modal = True
            self._log("GET", "/dashboard#help", 200)
            return self._view()
        if label == "Save":
            self.modal = False
            self._log("POST", "/dashboard#save", 200)
            return self._view()
        if label == "Delete":                         # destructive tripwire: ROE must prevent this
            self._log("DELETE", self.url, 200)
            self.url = "/orders"
            return self._view()
        if label == "Edit":
            self._log("PUT", self.url, 200)
            return self._view()
        if label == "Update":
            self._log("PUT", "/settings", 200)
            return self._view()
        if ui.url:                                    # a link click -> navigate
            return self.goto(ui.url)
        return self._view()

    def dismiss_modal(self) -> StateView:
        self.dismiss_calls += 1
        self.modal = False
        return self._view()

    # -- test helpers ------------------------------------------------------------------

    def methods(self) -> set[str]:
        return {e.method for e in self.har.entries}

    def urls(self) -> list[str]:
        return [e.url for e in self.har.entries]
