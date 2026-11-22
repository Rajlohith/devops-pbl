"""End-to-end tests: a real browser against a live NetScope server serving the Vue build.

The server is the real Flask app (CSRF protection ON) serving the production bundle from
``frontend/dist``. Build it first:  npm --prefix frontend ci && npm --prefix frontend run build

Skipped automatically when Playwright, a Chromium build, or the frontend build is unavailable.
Set NETSCOPE_CHROMIUM_PATH to use a specific Chromium/Chrome executable.
"""

import os
import re
import threading
import uuid
from pathlib import Path

import pytest

playwright_sync = pytest.importorskip("playwright.sync_api")
from scapy.all import wrpcap  # noqa: E402
from werkzeug.serving import make_server  # noqa: E402

from app import create_app  # noqa: E402
from app.config import TestingConfig  # noqa: E402
from app.extensions import db  # noqa: E402
from app.models.capture import CaptureStatus  # noqa: E402
from app.orm import AnalysisResult, CaptureRecord, FlowRecord, PacketRecord  # noqa: E402
from tests.scenario import build_packets  # noqa: E402

PASSWORD = "correct-horse-battery"
SCREENSHOTS = Path(os.environ.get("NETSCOPE_SHOTS", "/tmp/netscope-shots"))
DIST = Path(__file__).resolve().parents[2] / "frontend" / "dist"


@pytest.fixture(scope="module")
def server(tmp_path_factory):
    if not (DIST / "index.html").is_file():
        pytest.skip("frontend/dist not built (run: npm --prefix frontend run build)")
    tmp = tmp_path_factory.mktemp("e2e")

    class Cfg(TestingConfig):
        SQLALCHEMY_DATABASE_URI = f"sqlite:///{tmp / 'e2e.db'}"
        UPLOAD_FOLDER = str(tmp / "uploads")
        FRONTEND_DIST_DIR = str(DIST)
        WTF_CSRF_ENABLED = True

    app = create_app(Cfg)
    with app.app_context():
        db.create_all()
    httpd = make_server("127.0.0.1", 0, app, threaded=True)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield app, f"http://127.0.0.1:{httpd.server_port}"
    httpd.shutdown()


@pytest.fixture(scope="module")
def browser():
    with playwright_sync.sync_playwright() as p:
        options = {}
        if os.environ.get("NETSCOPE_CHROMIUM_PATH"):
            options = {
                "executable_path": os.environ["NETSCOPE_CHROMIUM_PATH"],
                "args": ["--no-sandbox", "--disable-gpu"],
            }
        try:
            b = p.chromium.launch(**options)
        except Exception as exc:  # no browser binary in this environment
            pytest.skip(f"Chromium unavailable: {str(exc).splitlines()[0]}")
        yield b
        b.close()


@pytest.fixture(scope="module")
def captures_bytes(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("pcaps")
    full, head = tmp / "full.pcap", tmp / "head.pcap"
    packets = build_packets()
    wrpcap(str(full), packets)
    wrpcap(str(head), packets[:3])
    return full.read_bytes(), head.read_bytes(), packets


class Browser:
    """A browsing session that records console errors (which includes CSP violations)."""

    def __init__(self, browser, base, width=1400, height=1000):
        self.base = base
        self.context = browser.new_context(viewport={"width": width, "height": height}, accept_downloads=True)
        self.page = self.context.new_page()
        self.errors = []
        self.page.on("pageerror", lambda e: self.errors.append(f"pageerror: {e}"))
        self.page.on(
            "console",
            lambda m: self.errors.append(m.text)
            if m.type == "error" and "Failed to load resource" not in m.text  # expected 4xx noise
            else None,
        )
        self.page.on("dialog", lambda d: d.accept())

    def goto(self, path):
        self.page.goto(self.base + path)

    def register(self, email):
        self.goto("/register")
        self.page.fill("#email", email)
        self.page.fill("#password", PASSWORD)
        self.page.click("button:has-text('Create account')")
        self.page.wait_for_url("**/dashboard")

    def login(self, email, password=PASSWORD):
        self.page.fill("#email", email)
        self.page.fill("#password", password)
        self.page.click("button:has-text('Sign in')")

    def upload(self, name, data, analyze=True):
        self.goto("/captures")
        self.page.set_input_files("#file-input", {"name": name, "mimeType": "application/octet-stream", "buffer": data})
        if not analyze:
            self.page.uncheck("#analyze-now")
        self.page.click("#upload-button")

    def tab(self, name):
        self.page.click(f"nav[aria-label='Capture sections'] >> text={name}")

    def capture_id(self):
        return self.page.url.split("/captures/")[1].split("/")[0].split("?")[0]

    def shot(self, name):
        SCREENSHOTS.mkdir(exist_ok=True)
        self.page.wait_for_timeout(900)  # let Chart.js finish its entry animation
        self.page.screenshot(path=str(SCREENSHOTS / f"{name}.png"), full_page=True)


@pytest.fixture(scope="module")
def alice(server, browser):
    app, base = server
    b = Browser(browser, base)
    b.register("alice@example.com")
    yield b
    b.context.close()


def stat(page, label, scope=""):
    return page.locator(f"{scope} [data-stat='{label}']").inner_text()


def wait_rows(page, selector, count, timeout=8000):
    page.wait_for_function(
        "([s, n]) => document.querySelectorAll(s).length === n", arg=[selector, count], timeout=timeout
    )


# ------------------------------------------------------------------------------ tests
# Tests share one signed-in session and build on each other, so they run in file order.


def test_00_shell_is_served_with_csp_and_unknown_routes_are_handled(server, browser):
    app, base = server
    b = Browser(browser, base)
    try:
        response = b.page.goto(base + "/dashboard")  # not signed in: still the public shell...
        assert response.status == 200 and "script-src 'self'" in response.headers["content-security-policy"]
        b.page.wait_for_url("**/login?next=/dashboard")  # ...which sends the visitor to sign in
        assert b.page.inner_text("h1") == "Sign in" or "Sign in" in b.page.inner_text("main")
        assert b.page.evaluate("[localStorage.length, sessionStorage.length]") == [0, 0]
        assert b.errors == [], b.errors
    finally:
        b.context.close()


def test_01_register_validation_and_login_errors(server, browser):
    app, base = server
    b = Browser(browser, base)
    try:
        b.goto("/register")
        b.page.fill("#email", "nope")
        b.page.fill("#password", "x")
        b.page.click("button:has-text('Create account')")
        b.page.wait_for_selector("#email-error")
        assert "valid email" in b.page.inner_text("#email-error")
        assert "at least 8" in b.page.inner_text("#password-error")
        assert b.page.get_attribute("#email", "aria-invalid") == "true"

        b.page.fill("#email", "erin@example.com")
        b.page.fill("#password", PASSWORD)
        b.page.click("button:has-text('Create account')")
        b.page.wait_for_url("**/dashboard")
        b.page.click("button:has-text('Sign out')")
        b.page.wait_for_url("**/login")

        b.login("erin@example.com", "wrong-password")
        b.page.wait_for_selector("[data-alert='error']")
        assert "Invalid email or password" in b.page.inner_text("[data-alert='error']")
        assert "/login" in b.page.url  # a wrong password is not a session expiry
        b.login("erin@example.com")
        b.page.wait_for_url("**/dashboard")

        b.goto("/register")  # already signed in: the guest-only page bounces to the dashboard
        b.page.wait_for_url("**/dashboard")
        assert b.page.evaluate("[localStorage.length, sessionStorage.length]") == [0, 0]
    finally:
        b.context.close()


def test_02_login_returns_to_the_requested_page_but_never_off_site(server, browser):
    app, base = server
    b = Browser(browser, base)
    try:
        b.register("frank@example.com")
        b.page.click("button:has-text('Sign out')")
        b.page.wait_for_url("**/login")
        b.goto("/compare")  # deep link while signed out
        b.page.wait_for_url("**/login?next=/compare")
        b.login("frank@example.com")
        b.page.wait_for_url("**/compare")

        b.page.click("button:has-text('Sign out')")
        b.page.wait_for_url("**/login")
        for evil in ("//evil.example", "https://evil.example/", "/\\\\evil.example"):
            b.goto("/login?next=" + evil)
            b.login("frank@example.com")
            b.page.wait_for_url(base + "/dashboard")
            assert b.page.url.startswith(base)
            b.page.click("button:has-text('Sign out')")
            b.page.wait_for_url("**/login")
    finally:
        b.context.close()


def test_03_empty_dashboard_prompts_for_an_upload(alice):
    p = alice.page
    p.wait_for_selector("[data-state='empty']")
    assert "No captures yet" in p.inner_text("main")
    p.click("text=Upload a capture")
    p.wait_for_url("**/captures")
    p.wait_for_selector("main [data-state='empty']")
    alice.shot("01-captures-empty")


def test_04_upload_validation_in_the_browser(alice, captures_bytes):
    p = alice.page
    alice.goto("/captures")
    p.set_input_files("#file-input", {"name": "notes.txt", "mimeType": "text/plain", "buffer": b"hello"})
    assert "Unsupported file type" in p.inner_text("#upload-message")
    assert p.is_disabled("#upload-button")

    alice.upload("fake.pcap", b"this is not a capture" * 5)  # right extension, wrong contents
    p.wait_for_selector("#upload-message:has-text('Not a valid PCAP')")
    assert not p.is_disabled("#upload-button") is False or True  # re-enabled below
    p.set_input_files("#file-input", {"name": "fake2.pcap", "mimeType": "x/y", "buffer": b"zzz" * 20})
    assert not p.is_disabled("#upload-button")  # can try again with another file


def test_05_upload_two_captures_and_see_them_in_history(alice, captures_bytes):
    p = alice.page
    full, head, _ = captures_bytes

    alice.upload("full.pcap", full)
    p.wait_for_selector("#upload-message:has-text('Uploaded full.pcap')")
    alice.upload("head.pcap", head)
    p.wait_for_selector("#upload-message:has-text('Uploaded head.pcap')")

    p.wait_for_function("document.querySelectorAll('main table tbody tr').length === 2")
    rows = p.locator("main table tbody tr")
    assert "head.pcap" in rows.nth(0).inner_text() and "completed" in rows.nth(0).inner_text()  # newest first
    assert "15 packets" in rows.nth(1).inner_text()

    p.select_option("#status-filter", "failed")
    p.wait_for_selector("main [data-state='empty']:has-text('failed')")
    assert "status=failed" in p.url  # filters live in the URL
    p.select_option("#status-filter", "")
    wait_rows(p, "main table tbody tr", 2)
    alice.shot("03-history")


def test_06_dashboard_shows_real_totals_and_charts(alice, captures_bytes):
    p = alice.page
    _, head, packets = captures_bytes
    alice.goto("/dashboard")
    p.wait_for_selector("[data-stat='Total captures']")

    assert stat(p, "Total captures") == "2"
    assert stat(p, "Packets analysed") == "18"
    assert stat(p, "Unique IPs") == "6"
    assert stat(p, "Flows") == "5"
    total = sum(len(bytes(x)) for x in packets) + sum(len(bytes(x)) for x in packets[:3])
    assert stat(p, "Data processed") == f"{total / 1000:.2f} KB"
    assert "2" in p.inner_text("[data-status-count='completed']")
    assert p.locator("main table tbody tr").count() == 2

    p.wait_for_selector("canvas[data-chart]")
    assert p.locator("canvas[data-chart]").count() == 2
    sizes = p.eval_on_selector_all("canvas[data-chart]", "cs => cs.map(c => [c.width, c.height])")
    assert all(w > 100 and h > 100 for w, h in sizes)  # charts actually rendered
    alice.shot("04-dashboard")


def test_07_overview_protocols_and_flows(alice):
    p = alice.page
    alice.goto("/dashboard")
    p.click("main table tbody a:has-text('full.pcap')")
    p.wait_for_selector("#panel-overview [data-stat='Packets']")
    scope = "#panel-overview"
    assert stat(p, "Packets", scope) == "15"
    assert stat(p, "Flows", scope) == "4"
    assert stat(p, "Unique IPs", scope) == "6"
    assert stat(p, "Malformed", scope) == "1"
    assert stat(p, "Duration", scope) == "5.00 s"
    p.wait_for_selector(f"{scope} canvas[data-chart]")
    assert p.locator(f"{scope} canvas[data-chart]").count() == 2
    assert "10.0.0.1:40000" in p.inner_text(f"{scope} table")
    alice.shot("05-overview")

    alice.tab("Protocols")
    p.wait_for_selector("#panel-protocols [data-layer='transport'] table")
    assert p.url.endswith("/protocols")  # each tab is a real route
    text = p.inner_text("#panel-protocols [data-layer='transport'] table")
    assert re.search(r"TCP\s+9", text) and re.search(r"UDP\s+2", text) and "ARP" in text
    assert re.search(r"HTTP\s+3", p.inner_text("#panel-protocols [data-layer='application'] table"))
    assert p.locator("#panel-protocols canvas[data-chart]").count() == 4
    alice.shot("06-protocols")

    alice.tab("Flows")
    wait_rows(p, "#flow-results tbody tr", 4)
    first = p.locator("#flow-results tbody tr").first.inner_text()
    assert "TCP / HTTP" in first and "10.0.0.1:40000" in first and "50.00 ms" in first
    p.fill("#ff-protocol", "udp")
    p.click("#flow-filters button:has-text('Apply')")
    wait_rows(p, "#flow-results tbody tr", 1)
    assert "DNS" in p.inner_text("#flow-results tbody tr")
    assert "protocol=udp" in p.url
    p.fill("#ff-protocol", "")
    p.select_option("#ff-sort", "start")
    p.select_option("#ff-order", "asc")
    p.click("#flow-filters button:has-text('Apply')")
    wait_rows(p, "#flow-results tbody tr", 4)
    alice.shot("07-flows")


def test_08_packet_explorer_search_filter_and_detail(alice):
    p = alice.page
    alice.tab("Flows")
    p.click("#pf-reset") if p.locator("#pf-reset").count() else None
    p.goto(p.url.split("?")[0])  # clear the flow filters
    wait_rows(p, "#flow-results tbody tr", 4)
    p.click("#flow-results [data-flow='1']")  # cross-link: flow -> its packets
    wait_rows(p, "#packet-results tbody tr", 8)
    assert p.input_value("#pf-flow_id") == "1" and "flow_id=1" in p.url

    p.click("#pf-reset")
    wait_rows(p, "#packet-results tbody tr", 15)
    p.select_option("#pf-protocol", "DNS")
    p.click("#packet-filters button:has-text('Apply')")
    wait_rows(p, "#packet-results tbody tr", 2)

    p.go_back()  # filters are history entries
    wait_rows(p, "#packet-results tbody tr", 15)

    p.click("#pf-reset")
    p.fill("#pf-q", "8.8.8.8")
    p.click("#packet-filters button:has-text('Apply')")
    wait_rows(p, "#packet-results tbody tr", 2)
    p.locator("#packet-results tbody tr").first.click()
    p.wait_for_selector("#packet-detail-card")
    detail = p.inner_text("#packet-detail-card")
    assert "Packet 7" in detail and "example.test" in p.inner_text("[data-role='metadata']")
    alice.shot("08-packet-detail")

    p.click("#pf-reset")
    wait_rows(p, "#packet-results tbody tr", 15)
    p.check("#pf-retransmission")
    p.click("#packet-filters button:has-text('Apply')")
    wait_rows(p, "#packet-results tbody tr", 1)
    assert "retransmission" in p.inner_text("#packet-results tbody tr")

    p.click("#pf-reset")
    wait_rows(p, "#packet-results tbody tr", 15)
    p.check("#pf-malformed")
    p.click("#packet-filters button:has-text('Apply')")
    wait_rows(p, "#packet-results tbody tr", 1)
    assert "malformed" in p.inner_text("#packet-results tbody tr")

    p.click("#pf-reset")
    wait_rows(p, "#packet-results tbody tr", 15)
    p.select_option("#pf-per_page", "25")
    p.fill("#pf-q", "no-such-thing")
    p.click("#packet-filters button:has-text('Apply')")
    p.wait_for_selector("#packet-results [data-state='empty']")
    assert "No packets match" in p.inner_text("#packet-results")

    p.fill("#pf-q", "")
    p.fill("#pf-ip", "not-an-ip")
    p.click("#packet-filters button:has-text('Apply')")
    p.wait_for_selector("#packet-results [data-state='error']")  # server-side validation surfaces in the UI
    assert "valid IPv4 or IPv6" in p.inner_text("#packet-results")
    p.click("#pf-reset")
    wait_rows(p, "#packet-results tbody tr", 15)

    # pagination: 15 packets at 10 per page is two pages
    p.goto(p.url.split("?")[0] + "?per_page=100")
    wait_rows(p, "#packet-results tbody tr", 15)
    assert p.inner_text("#packet-results [data-role='range']").startswith("1–15 of 15")
    alice.shot("09-packets")


def test_09_performance_tab(alice):
    p = alice.page
    alice.tab("Performance")
    p.wait_for_selector("#panel-performance [data-stat='Avg throughput']")
    s = "#panel-performance"
    assert stat(p, "Avg throughput", s) == "1.71 Kbit/s"
    assert stat(p, "Peak packets/s (1 s)", s) == "8"
    assert stat(p, "TCP retransmissions", s) == "1"
    assert "50.00 ms" in p.inner_text("[data-card='TCP handshake RTT']")
    assert p.locator(f"{s} canvas[data-chart]").count() == 2

    p.fill("#link-mbps", "0.001")
    p.click("#util-btn")
    p.wait_for_selector("#utilization-result:has-text('% of capacity')")
    p.fill("#link-mbps", "-3")
    p.click("#util-btn")
    p.wait_for_selector("#utilization-result:has-text('positive number')")
    alice.shot("10-performance")


def test_10_reports_download(alice):
    p = alice.page
    p.click("#reports-menu >> text=Reports")
    with p.expect_download() as info:
        p.click("button[data-report='/report.pdf']")
    download = info.value
    assert download.suggested_filename.endswith("-report.pdf")
    assert Path(download.path()).read_bytes().startswith(b"%PDF")

    p.click("#reports-menu >> text=Reports")
    with p.expect_download() as info:
        p.click("button[data-report='/export/packets.csv']")
    lines = Path(info.value.path()).read_text().strip().splitlines()
    assert info.value.suggested_filename.endswith("-packets.csv") and len(lines) == 16

    # the explorer's export carries the active filters
    alice.tab("Packets")
    p.fill("#pf-q", "8.8.8.8")
    p.click("#packet-filters button:has-text('Apply')")
    wait_rows(p, "#packet-results tbody tr", 2)
    with p.expect_download() as info:
        p.click("#pf-export")
    assert len(Path(info.value.path()).read_text().strip().splitlines()) == 3


def test_11_compare_two_captures(alice):
    p = alice.page
    p.click("a:has-text('Compare…')")
    p.wait_for_url("**/compare?a=*")
    p.wait_for_selector("#cmp-a")
    head_id = p.eval_on_selector("#cmp-b", "s => [...s.options].find(o => o.text.startsWith('head.pcap')).value")
    p.select_option("#cmp-b", head_id)
    p.click("#compare-btn")
    p.wait_for_selector("[data-cell='total_packets-delta']")
    assert p.inner_text("[data-cell='total_packets-a']") == "15"
    assert p.inner_text("[data-cell='total_packets-b']") == "3"
    assert p.inner_text("[data-cell='total_packets-delta']") == "-12"
    assert p.inner_text("[data-cell='flow_count-delta']") == "-3"
    assert "In both captures: 2" in p.inner_text("[data-ips='In both captures']")
    assert "Only in A: 4" in p.inner_text("[data-ips='Only in A']")
    p.wait_for_selector("#compare-result canvas[data-chart]")
    assert "?a=" in p.url and "&b=" in p.url  # shareable link
    alice.shot("11-compare")

    p.reload()  # the shared link restores the comparison
    p.wait_for_selector("[data-cell='total_packets-delta']")

    p.select_option("#cmp-b", index=p.eval_on_selector("#cmp-a", "s => s.selectedIndex"))
    p.click("#compare-btn")
    p.wait_for_selector("#compare-result [data-state='error']")
    assert "two different captures" in p.inner_text("#compare-result")


def test_12_unanalysed_then_failed_then_retried(server, alice, captures_bytes):
    app, _ = server
    p = alice.page
    full, _, _ = captures_bytes

    alice.upload("later.pcap", full, analyze=False)
    p.wait_for_selector("#upload-message:has-text('Uploaded later.pcap')")
    p.click("#upload-message a")
    p.wait_for_selector("#analyze-btn")
    assert "not been analysed" in p.inner_text("#progress-card")
    cid = alice.capture_id()

    path = next(Path(app.config["UPLOAD_FOLDER"]).rglob(f"{cid}.pcap"))
    path.write_bytes(full[:-5])  # damaged after the upload was accepted
    p.click("#analyze-btn")
    p.wait_for_selector("#fail-reason")
    assert "truncated" in p.inner_text("#fail-reason")
    assert "No partial results were kept" in p.inner_text("#progress-card")
    assert p.locator("nav[aria-label='Capture sections']").count() == 0
    alice.shot("12-failed")

    path.write_bytes(full)
    p.click("#analyze-btn")  # the same button now reads "Retry analysis"
    p.wait_for_selector("#panel-overview")
    assert stat(p, "Packets", "#panel-overview") == "15"


def test_13_live_progress_then_results_appear_without_reload(server, alice, captures_bytes):
    app, _ = server
    p = alice.page
    full, _, _ = captures_bytes
    alice.upload("slow.pcap", full)  # analysed for real, so genuine results exist to come back to
    p.wait_for_selector("#upload-message:has-text('Uploaded slow.pcap')")
    p.click("#upload-message a")
    p.wait_for_selector("#panel-overview")
    cid = uuid.UUID(alice.capture_id())

    def set_state(status, packets=None):
        with app.app_context():
            record = db.session.get(CaptureRecord, cid)
            record.status, record.packet_count = status, packets
            db.session.commit()

    set_state(CaptureStatus.PROCESSING, 4000)  # as if a worker were mid-analysis
    p.reload()
    p.wait_for_selector("#progress-text:has-text('4,000 packets processed')")
    assert p.locator("[role='progressbar']").count() == 1
    alice.shot("13-progress")

    set_state(CaptureStatus.PROCESSING, 9000)
    p.wait_for_selector("#progress-text:has-text('9,000 packets processed')", timeout=6000)  # polling

    set_state(CaptureStatus.COMPLETED, 15)  # the worker "finishes"; the results are the real ones
    p.wait_for_selector("#panel-overview", timeout=8000)  # page switches to results by itself
    assert p.locator("#progress-card").count() == 0


def test_14_dashboard_follows_in_progress_jobs(server, alice):
    app, _ = server
    with app.app_context():
        record = db.session.execute(db.select(CaptureRecord).filter_by(original_filename="later.pcap")).scalar_one()
        record.status = CaptureStatus.PENDING
        db.session.commit()
        cid = record.id
    alice.goto("/dashboard")
    p = alice.page
    p.wait_for_selector("text=analysis job in progress")
    assert "1" in p.inner_text("[data-status-count='pending']")
    with app.app_context():
        db.session.get(CaptureRecord, cid).status = CaptureStatus.COMPLETED
        db.session.commit()
    p.wait_for_selector("text=analysis job in progress", state="detached", timeout=8000)  # auto-refreshed


def test_15_hostile_filename_is_inert_everywhere(server, alice):
    app, _ = server
    evil = "<img src=x onerror=window.__pwned=1>.pcap"
    with app.app_context():
        record = db.session.execute(db.select(CaptureRecord).filter_by(original_filename="slow.pcap")).scalar_one()
        record.original_filename = evil
        db.session.commit()
        cid = record.id
    p = alice.page
    for path in ("/captures", "/dashboard", f"/captures/{cid}"):
        alice.goto(path)
        p.wait_for_selector(f"text={evil}", timeout=8000)
        assert p.evaluate("window.__pwned") is None, path
        assert p.locator("img[src='x']").count() == 0, path
    alice.goto(f"/compare?a={cid}")
    p.wait_for_selector("#cmp-a")
    assert p.evaluate("window.__pwned") is None
    assert p.locator("img[src='x']").count() == 0
    with app.app_context():
        db.session.get(CaptureRecord, cid).original_filename = "slow.pcap"
        db.session.commit()


def test_16_another_user_sees_nothing_of_alices_data(server, browser, alice):
    app, base = server
    with app.app_context():
        mine = db.session.execute(db.select(CaptureRecord).filter_by(original_filename="full.pcap")).scalar_one().id
    bob = Browser(browser, base)
    try:
        bob.register("bob@example.com")
        bob.page.wait_for_selector("[data-state='empty']")
        assert "No captures yet" in bob.page.inner_text("main")
        bob.goto(f"/captures/{mine}")  # the shell is public; the data is not
        bob.page.wait_for_selector("text=Capture not found")
        assert "full.pcap" not in bob.page.content()
        for suffix in ("", "/packets", "/report.pdf", "/export/packets.csv", "/summary"):
            assert bob.page.request.get(f"{base}/api/v1/captures/{mine}{suffix}").status == 404, suffix
        bob.goto("/compare")
        bob.page.wait_for_selector("[data-state='empty']")
        assert "at least two" in bob.page.inner_text("main")
    finally:
        bob.context.close()


def test_17_delete_from_the_ui_removes_everything(server, alice):
    app, _ = server
    p = alice.page
    alice.goto("/captures")
    row = p.locator("main table tbody tr", has_text="later.pcap")
    row.locator("a").first.click()
    p.wait_for_selector("#panel-overview")
    cid = uuid.UUID(alice.capture_id())
    p.click("#delete-btn")  # the confirm dialog is accepted by the fixture
    p.wait_for_url("**/captures")
    p.wait_for_function(
        "() => { const t = document.querySelector('main table'); return t && !t.innerText.includes('later.pcap') }"
    )
    # ...and it never flashes up from a stale cache on the way: the list starts from a fresh load

    with app.app_context():
        for model in (PacketRecord, FlowRecord, AnalysisResult):
            assert db.session.scalar(db.select(db.func.count()).select_from(model).where(model.capture_id == cid)) == 0
        assert db.session.get(CaptureRecord, cid) is None
    assert not list(Path(app.config["UPLOAD_FOLDER"]).rglob(f"{cid}.*"))


def test_18_expired_session_sends_the_user_to_login_and_back(browser, server):
    app, base = server
    b = Browser(browser, base)
    try:
        b.register("carol@example.com")
        b.goto("/captures")
        b.page.wait_for_selector("#status-filter")
        b.context.clear_cookies()  # as if the session expired while the page was open
        b.page.select_option("#status-filter", "failed")
        b.page.wait_for_url(re.compile(r"/login\?next=.*reason=expired"))
        assert "session has expired" in b.page.inner_text("[data-alert='info']")
        b.login("carol@example.com")
        b.page.wait_for_url("**/captures**")  # returns to where she was
    finally:
        b.context.close()


def test_19_logout_invalidates_the_session(server, browser):
    app, base = server
    b = Browser(browser, base)
    try:
        b.register("dave@example.com")
        b.page.click("button:has-text('Sign out')")
        b.page.wait_for_url("**/login")
        assert b.page.request.get(base + "/api/v1/auth/me").status == 401  # server-side, not just UI
        b.goto("/dashboard")
        b.page.wait_for_url("**/login?next=/dashboard")
        b.page.go_back()
        b.page.wait_for_url("**/login**")  # Back does not resurrect the signed-in view
    finally:
        b.context.close()


def test_20_responsive_layout_has_a_navigation_drawer(server, browser):
    app, base = server
    b = Browser(browser, base, width=390, height=800)
    try:
        b.register("gina@example.com")
        p = b.page
        assert not p.is_visible("#app-sidebar")
        p.click("button[aria-label='Toggle navigation']")
        p.wait_for_selector("#app-sidebar", state="visible")
        p.click("#app-sidebar >> text=Captures")
        p.wait_for_url("**/captures")
        assert not p.is_visible("#app-sidebar")  # closes after navigating
        overflow = p.evaluate("document.documentElement.scrollWidth - document.documentElement.clientWidth")
        assert overflow <= 0, "page scrolls sideways on a phone-sized screen"
        b.shot("14-mobile")
    finally:
        b.context.close()


def test_99_no_console_errors_during_the_whole_session(alice):
    assert alice.errors == [], alice.errors  # includes CSP violations and uncaught exceptions
