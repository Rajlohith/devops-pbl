"""End-to-end tests: a real browser against a live NetScope server.

Skipped automatically when Playwright or a Chromium build is unavailable. CSRF
protection is ON here, so every request the JavaScript makes must carry a valid token.
"""

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
SCREENSHOTS = Path("/tmp/netscope-shots")


@pytest.fixture(scope="module")
def server(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("e2e")

    class Cfg(TestingConfig):
        SQLALCHEMY_DATABASE_URI = f"sqlite:///{tmp / 'e2e.db'}"
        UPLOAD_FOLDER = str(tmp / "uploads")
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
        try:
            b = p.chromium.launch()
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
    """A logged-in browsing session that records console errors."""

    def __init__(self, browser, base):
        self.base = base
        self.context = browser.new_context(viewport={"width": 1400, "height": 1000}, accept_downloads=True)
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
        self.page.click("button:has-text('Register')")
        self.page.wait_for_url("**/dashboard")

    def upload(self, name, data, analyze=True):
        self.goto("/captures")
        self.page.set_input_files("#file-input", {"name": name, "mimeType": "application/octet-stream", "buffer": data})
        if not analyze:
            self.page.uncheck("#analyze-now")
        self.page.click("#upload-button")

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
# Tests share one logged-in session and build on each other, so they run in file order.


def test_01_empty_dashboard_prompts_for_an_upload(alice):
    p = alice.page
    p.wait_for_selector("[data-state='empty']")
    assert "No captures yet" in p.inner_text("#dashboard-root")
    p.click("text=Upload a capture")
    p.wait_for_url("**/captures")
    p.wait_for_selector("#history-root [data-state='empty']")
    alice.shot("01-captures-empty")


def test_02_upload_validation_in_the_browser(alice, captures_bytes):
    p = alice.page
    full, head, _ = captures_bytes

    alice.goto("/captures")
    p.set_input_files("#file-input", {"name": "notes.txt", "mimeType": "text/plain", "buffer": b"hello"})
    assert "Unsupported file type" in p.inner_text("#upload-message")
    assert p.is_disabled("#upload-button")

    alice.upload("fake.pcap", b"this is not a capture" * 5)  # right extension, wrong contents
    p.wait_for_selector("#upload-message:has-text('Not a valid PCAP')")
    assert not p.is_disabled("#upload-button")  # can try again


def test_03_upload_two_captures_and_see_them_in_history(alice, captures_bytes):
    p = alice.page
    full, head, _ = captures_bytes

    alice.upload("full.pcap", full)
    p.wait_for_selector("#upload-message:has-text('Uploaded full.pcap')")
    alice.upload("head.pcap", head)
    p.wait_for_selector("#upload-message:has-text('Uploaded head.pcap')")

    p.wait_for_function("document.querySelectorAll('#history-root tbody tr').length === 2")
    rows = p.locator("#history-root tbody tr")
    assert "head.pcap" in rows.nth(0).inner_text() and "completed" in rows.nth(0).inner_text()  # newest first
    assert "15 packets" in rows.nth(1).inner_text()

    p.select_option("#status-filter", "failed")
    p.wait_for_selector("#history-root [data-state='empty']")
    p.select_option("#status-filter", "")
    wait_rows(p, "#history-root tbody tr", 2)
    alice.shot("03-history")


def test_04_dashboard_shows_real_totals_and_charts(alice, captures_bytes):
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
    assert p.locator("#dashboard-root tbody tr").count() == 2

    p.wait_for_selector("canvas[data-chart]")
    assert p.locator("canvas[data-chart]").count() == 2
    sizes = p.eval_on_selector_all("canvas[data-chart]", "cs => cs.map(c => [c.width, c.height])")
    assert all(w > 100 and h > 100 for w, h in sizes)  # charts actually rendered
    alice.shot("04-dashboard")


def test_05_overview_protocols_and_flows(alice):
    p = alice.page
    alice.goto("/dashboard")
    p.click("#dashboard-root tbody a:has-text('full.pcap')")
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

    p.click("#tab-protocols")
    p.wait_for_selector("#panel-protocols [data-layer='transport'] table")
    text = p.inner_text("#panel-protocols [data-layer='transport'] table")
    assert re.search(r"TCP\s+9", text) and re.search(r"UDP\s+2", text) and "ARP" in text
    assert re.search(r"HTTP\s+3", p.inner_text("#panel-protocols [data-layer='application'] table"))
    assert p.locator("#panel-protocols canvas[data-chart]").count() == 4
    alice.shot("06-protocols")

    p.click("#tab-flows")
    wait_rows(p, "#flow-results tbody tr", 4)
    first = p.locator("#flow-results tbody tr").first.inner_text()
    assert "TCP / HTTP" in first and "10.0.0.1:40000" in first and "50.00 ms" in first
    p.fill("#ff-protocol", "udp")
    p.click("#flow-filters button:has-text('Apply')")
    wait_rows(p, "#flow-results tbody tr", 1)
    assert "DNS" in p.inner_text("#flow-results tbody tr")
    p.fill("#ff-protocol", "")
    p.select_option("#ff-sort", "start")
    p.select_option("#ff-order", "asc")
    p.click("#flow-filters button:has-text('Apply')")
    wait_rows(p, "#flow-results tbody tr", 4)
    alice.shot("07-flows")


def test_06_packet_explorer_search_filter_and_detail(alice):
    p = alice.page
    p.click("#tab-flows")
    wait_rows(p, "#flow-results tbody tr", 4)
    p.select_option("#ff-sort", "bytes")
    p.select_option("#ff-order", "desc")
    p.click("#flow-filters button:has-text('Apply')")
    wait_rows(p, "#flow-results tbody tr", 4)
    p.click("#flow-results [data-flow='1']")  # cross-link: flow -> its packets
    wait_rows(p, "#packet-results tbody tr", 8)
    assert p.input_value("#pf-flow_id") == "1"

    p.click("#pf-reset")
    wait_rows(p, "#packet-results tbody tr", 15)
    p.select_option("#pf-protocol", "DNS")
    p.click("#packet-filters button:has-text('Apply')")
    wait_rows(p, "#packet-results tbody tr", 2)

    p.click("#pf-reset")
    wait_rows(p, "#packet-results tbody tr", 15)
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
    alice.shot("09-packets")


def test_07_performance_tab(alice):
    p = alice.page
    p.click("#tab-performance")
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


def test_08_reports_download(alice):
    p = alice.page
    p.click("#reports-menu summary")
    with p.expect_download() as info:
        p.click("a[data-report='/report.pdf']")
    download = info.value
    path = download.path()
    assert download.suggested_filename.endswith("-report.pdf")
    assert Path(path).read_bytes().startswith(b"%PDF")

    p.click("#reports-menu summary")  # menu is still open after the download navigation
    csv = p.request.get(alice.base + p.locator("a[data-report='/export/packets.csv']").get_attribute("href"))
    assert csv.status == 200 and csv.headers["content-type"].startswith("text/csv")
    assert len(csv.text().strip().splitlines()) == 16

    # the explorer's export link carries the active filters
    p.click("#tab-packets")
    p.fill("#pf-q", "8.8.8.8")
    p.click("#packet-filters button:has-text('Apply')")
    wait_rows(p, "#packet-results tbody tr", 2)
    href = p.get_attribute("#pf-export", "href")
    filtered = p.request.get(alice.base + href)
    assert len(filtered.text().strip().splitlines()) == 3


def test_09_compare_two_captures(alice):
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

    p.select_option("#cmp-b", index=p.eval_on_selector("#cmp-a", "s => s.selectedIndex"))
    p.click("#compare-btn")
    p.wait_for_selector("#compare-result [data-state='error']")
    assert "two different captures" in p.inner_text("#compare-result")


def test_10_unanalysed_then_failed_then_retried(server, alice, captures_bytes):
    app, _ = server
    p = alice.page
    full, _, _ = captures_bytes

    alice.upload("later.pcap", full, analyze=False)
    p.wait_for_selector("#upload-message:has-text('Uploaded later.pcap')")
    p.click("#upload-message a")
    p.wait_for_selector("#analyze-btn")
    assert "not been analysed" in p.inner_text("#progress-card")
    cid = p.url.split("/captures/")[1].split("#")[0]

    path = next(Path(app.config["UPLOAD_FOLDER"]).rglob(f"{cid}.pcap"))
    path.write_bytes(full[:-5])  # damaged after the upload was accepted
    p.click("#analyze-btn")
    p.wait_for_selector("#fail-reason")
    assert "truncated" in p.inner_text("#fail-reason")
    assert "No partial results were kept" in p.inner_text("#progress-card")
    assert p.locator("#tab-bar:visible").count() == 0
    alice.shot("12-failed")

    path.write_bytes(full)
    p.click("#analyze-btn")  # the same button now reads "Retry analysis"
    p.wait_for_selector("#tab-overview")
    assert stat(p, "Packets", "#panel-overview") == "15"


def test_11_live_progress_then_results_appear_without_reload(server, alice, captures_bytes):
    app, _ = server
    p = alice.page
    full, _, _ = captures_bytes
    alice.upload("slow.pcap", full, analyze=False)
    p.wait_for_selector("#upload-message:has-text('Uploaded slow.pcap')")
    p.click("#upload-message a")
    p.wait_for_selector("#analyze-btn")
    cid = uuid.UUID(p.url.split("/captures/")[1].split("#")[0])

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

    set_state(CaptureStatus.COMPLETED, 15)  # results already stored by the real earlier run
    p.wait_for_selector("#tab-overview", timeout=8000)  # page switches to results by itself
    assert p.locator("#progress-card").count() == 0


def test_12_dashboard_follows_in_progress_jobs(server, alice):
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


def test_13_hostile_filename_is_inert_everywhere(server, alice):
    app, _ = server
    evil = "<img src=x onerror=window.__pwned=1>.pcap"
    with app.app_context():
        record = db.session.execute(db.select(CaptureRecord).filter_by(original_filename="slow.pcap")).scalar_one()
        record.original_filename = evil
        db.session.commit()
        cid = record.id
    p = alice.page
    for path in ("/captures", "/dashboard", f"/captures/{cid}", f"/compare?a={cid}"):
        alice.goto(path)
        p.wait_for_selector(f"text={evil}", timeout=8000) if path != "/compare?a=" + str(cid) else p.wait_for_selector("#cmp-a")
        assert p.evaluate("window.__pwned") is None, path
        assert p.locator("img[src='x']").count() == 0, path
    with app.app_context():
        db.session.get(CaptureRecord, cid).original_filename = "slow.pcap"
        db.session.commit()


def test_14_another_user_sees_nothing_of_alices_data(server, browser, alice):
    app, base = server
    with app.app_context():
        mine = db.session.execute(db.select(CaptureRecord).filter_by(original_filename="full.pcap")).scalar_one().id
    bob = Browser(browser, base)
    try:
        bob.register("bob@example.com")
        bob.page.wait_for_selector("[data-state='empty']")
        assert "No captures yet" in bob.page.inner_text("#dashboard-root")
        response = bob.page.goto(f"{base}/captures/{mine}")
        assert response.status == 404
        api = bob.page.request.get(f"{base}/api/v1/captures/{mine}/packets")
        assert api.status == 404
        assert bob.page.request.get(f"{base}/api/v1/captures/{mine}/report.pdf").status == 404
        bob.goto("/compare")
        bob.page.wait_for_selector("[data-state='empty']")
        assert "at least two" in bob.page.inner_text("#compare-root")
    finally:
        bob.context.close()


def test_15_delete_from_the_ui_removes_everything(server, alice):
    app, _ = server
    p = alice.page
    alice.goto("/captures")
    row = p.locator("#history-root tbody tr", has_text="later.pcap")
    row.locator("a").first.click()
    p.wait_for_selector("#tab-overview")
    cid = uuid.UUID(p.url.split("/captures/")[1].split("#")[0])
    p.click("#delete-btn")  # the confirm dialog is accepted by the fixture
    p.wait_for_url("**/captures")
    p.wait_for_selector("#history-root tbody tr")
    assert "later.pcap" not in p.inner_text("#history-root")

    with app.app_context():
        for model in (PacketRecord, FlowRecord, AnalysisResult):
            assert db.session.scalar(db.select(db.func.count()).select_from(model).where(model.capture_id == cid)) == 0
        assert db.session.get(CaptureRecord, cid) is None
    assert not list(Path(app.config["UPLOAD_FOLDER"]).rglob(f"{cid}.*"))


def test_16_expired_session_sends_the_user_to_login(browser, server):
    app, base = server
    b = Browser(browser, base)
    try:
        b.register("carol@example.com")
        b.goto("/captures")
        b.page.wait_for_selector("#status-filter")
        b.context.clear_cookies()  # as if the session expired while the page was open
        b.page.select_option("#status-filter", "failed")
        b.page.wait_for_url("**/login?next=%2Fcaptures")
        assert "Log in" in b.page.inner_text("h1")
    finally:
        b.context.close()


def test_17_logout_via_the_nav(server, browser):
    app, base = server
    b = Browser(browser, base)
    try:
        b.register("dave@example.com")
        b.page.click("button:has-text('Log out')")
        b.page.wait_for_url("**/login")
        b.goto("/dashboard")
        b.page.wait_for_url("**/login?next=/dashboard")
    finally:
        b.context.close()


def test_99_no_console_errors_during_the_whole_session(alice):
    assert alice.errors == [], alice.errors
