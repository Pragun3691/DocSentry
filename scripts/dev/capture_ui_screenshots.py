import io
import sys
import time
import subprocess
import urllib.request
from pathlib import Path
from PIL import Image
from playwright.sync_api import sync_playwright

CHROME = r"C:\Program Files\Google\Chrome\Application\chrome.exe"
if not Path(CHROME).exists():
    print(f"Error: Chrome binary not found at {CHROME}")
    sys.exit(1)

BASE_DIR = Path(__file__).resolve().parent.parent
FIGURES_DIR = BASE_DIR / "reports" / "figures"
FIGURES_DIR.mkdir(parents=True, exist_ok=True)
SYNTH_DIR = BASE_DIR / "data" / "demo_pdfs" / "synthetic"

PORT = 8016
BASE_URL = f"http://127.0.0.1:{PORT}"
MAX_SLICE_H = 1400

print(f"Starting DocSentry FastAPI server on port {PORT}...")
proc = subprocess.Popen(
    [sys.executable, "-m", "uvicorn", "app.main:app", "--port", str(PORT), "--host", "127.0.0.1"],
    cwd=str(BASE_DIR),
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL,
)

ready = False
for _ in range(30):
    try:
        if urllib.request.urlopen(f"{BASE_URL}/health", timeout=1).status == 200:
            ready = True
            break
    except Exception:
        time.sleep(0.5)

if not ready:
    print("Error: Server failed to start.")
    proc.kill()
    sys.exit(1)


def check_no_overflow(page, label: str):
    res = page.evaluate("""() => {
        const sw = document.documentElement.scrollWidth;
        const cw = document.documentElement.clientWidth;
        const bad = [];
        for (const el of document.querySelectorAll('*')) {
            const r = el.getBoundingClientRect();
            if (r.width > 0 && r.right > cw + 1) {
                if (!el.closest('.chart-scroll-box') && !el.closest('.table-scroll-box') && !el.closest('.ticker-strip') && !el.closest('.sr-only')) {
                    bad.push({tag: el.tagName, id: el.id || '', right: Math.round(r.right), cw});
                }
            }
        }
        return {sw, cw, bad: bad.slice(0, 10)};
    }""")
    if res["sw"] > res["cw"] or res["bad"]:
        raise AssertionError(f"Horizontal overflow on {label}: {res}")
    print(f"  [OK] Overflow check: {label:<30} ({res['sw']} <= {res['cw']})")


def check_mobile_charts(page, label: str):
    res = page.evaluate("""() => {
        const cw = document.documentElement.clientWidth;
        const errors = [];
        for (const name of ['shap-chart', 'family-chart']) {
            const rows = document.getElementById(name).querySelectorAll('.chart-row');
            if (!rows.length) errors.push(`${name}: 0 rows`);
            rows.forEach((row, idx) => {
                const bar = row.querySelector('.chart-bar');
                const val = row.querySelector('.chart-svg-value');
                if (!bar || bar.getBoundingClientRect().width < 4) errors.push(`${name} row ${idx}: bar < 4px`);
                if (!val) errors.push(`${name} row ${idx}: missing value`);
                else {
                    const vr = val.getBoundingClientRect();
                    if (vr.width <= 0 || vr.right > cw + 1 || vr.left < -1) errors.push(`${name} row ${idx}: value clipped`);
                }
            });
        }
        return errors;
    }""")
    if res:
        raise AssertionError(f"Mobile chart check failed on {label}: {res}")


def check_gauge(page, label: str):
    res = page.evaluate("""() => {
        const errors = [];
        const track = document.querySelector('.gauge-track');
        if (track.innerText.trim() !== '') {
            errors.push(`Text inside gauge-track: ${track.innerText.trim()}`);
        }
        // Check duplicate words in zone labels
        for (const z of document.querySelectorAll('.gauge-zlabel')) {
            const words = z.innerText.trim().split(/\\s+/);
            const seen = new Set();
            for (const w of words) {
                if (seen.has(w)) errors.push(`Duplicate word '${w}' in ${z.className}`);
                seen.add(w);
            }
        }
        // Collect visible text leaf boxes inside .gauge-block
        const textBoxes = [];
        const candidates = document.querySelectorAll('.gauge-block .gauge-title, .gauge-block .gauge-val-mono, .gauge-block .gauge-zlabel, .gauge-block .gauge-ticks span, .gauge-block .needle-pill, .gauge-block .gauge-step-hint');
        for (const el of candidates) {
            const r = el.getBoundingClientRect();
            if (r.width > 0 && r.height > 0) {
                textBoxes.push({name: el.innerText.trim(), left: r.left, right: r.right, top: r.top, bottom: r.bottom});
            }
        }
        const overlap = (a, b) => !(a.right <= b.left + 0.5 || b.right <= a.left + 0.5 || a.bottom <= b.top + 0.5 || b.bottom <= a.top + 0.5);
        for (let i = 0; i < textBoxes.length; i++) {
            for (let j = i + 1; j < textBoxes.length; j++) {
                if (overlap(textBoxes[i], textBoxes[j])) {
                    errors.push(`Text overlap: '${textBoxes[i].name}' vs '${textBoxes[j].name}'`);
                }
            }
        }
        // Check needle & threshold do not cross any text box
        for (const sel of ['.gauge-needle', '.gauge-threshold']) {
            const mr = document.querySelector(sel).getBoundingClientRect();
            for (const tb of textBoxes) {
                if (overlap(mr, tb)) {
                    errors.push(`${sel} crosses text '${tb.name}'`);
                }
            }
        }
        return errors;
    }""")
    if res:
        raise AssertionError(f"Gauge check failed on {label}: {res}")
    print(f"  [OK] Gauge check:    {label}")


def check_ticker(page, theme: str):
    st = page.evaluate("""() => {
        const cs = getComputedStyle(document.querySelector('.ticker-strip'));
        return {bg: cs.backgroundColor, color: cs.color};
    }""")
    print(f"  [TICKER {theme.upper()}] background-color={st['bg']}, color={st['color']}")
    if theme == "dark":
        assert st["bg"] == "rgb(28, 28, 25)", f"Dark ticker bg must be card rgb(28, 28, 25), got {st['bg']}"
        assert st["color"] == "rgb(241, 239, 230)", f"Dark ticker color must be paper rgb(241, 239, 230), got {st['color']}"
    else:
        assert st["bg"] == "rgb(20, 20, 18)", f"Light ticker bg must be ink rgb(20, 20, 18), got {st['bg']}"
        assert st["color"] == "rgb(241, 239, 230)", f"Light ticker color must be paper rgb(241, 239, 230), got {st['color']}"


def save_sliced_fullpage(page, prefix: str):
    png_bytes = page.screenshot(full_page=True)
    img = Image.open(io.BytesIO(png_bytes))
    w, h = img.size
    part = 1
    for top in range(0, h, MAX_SLICE_H):
        bottom = min(top + MAX_SLICE_H, h)
        img.crop((0, top, w, bottom)).save(FIGURES_DIR / f"{prefix}_part{part}.png")
        part += 1
    print(f"    -> Saved {part - 1} slices ({w}x{h}) for {prefix}")


try:
    with sync_playwright() as p:
        browser = p.chromium.launch(executable_path=CHROME, headless=True)

        for theme in ["light", "dark"]:
            for w in [360, 390, 768, 1280]:
                for state in ["", "benign", "review", "malicious", "ood"]:
                    q = f"?theme={theme}" + (f"&demo={state}" if state else "")
                    page = browser.new_page(viewport={"width": w, "height": 900})
                    page.goto(f"{BASE_URL}/{q}", wait_until="domcontentloaded", timeout=60000)
                    if state:
                        page.wait_for_function("document.getElementById('result-section').style.display === 'block'", timeout=90000)
                    else:
                        page.wait_for_selector("#model-info-panel .model-stats-grid", timeout=30000)
                    page.evaluate("() => document.fonts ? document.fonts.ready : true")

                    if w == 1280 and not state:
                        check_ticker(page, theme)
                        # Top of page screenshot (ticker + header + hero)
                        page.screenshot(path=str(FIGURES_DIR / f"ui_v3_top_{theme}_1280.png"), clip={"x": 0, "y": 0, "width": 1280, "height": 760})

                    label = f"{theme} {w}px {state or 'empty'}"
                    check_no_overflow(page, label)
                    if state:
                        check_gauge(page, label)
                    if state and w in (360, 390):
                        check_mobile_charts(page, label)

                    if w in (1280, 390) and state:
                        state_slug = {"benign": "benign", "review": "needs_review", "malicious": "likely_malicious", "ood": "ood"}[state]
                        save_sliced_fullpage(page, f"ui_v3_{theme}_{state_slug}_{w}")

                    # Close-ups: gauge at 1280 & 390 for benign, review, malicious
                    if state in ("benign", "review", "malicious") and w in (1280, 390):
                        slug = {"benign": "benign", "review": "needs_review", "malicious": "malicious"}[state]
                        page.locator(".gauge-block").scroll_into_view_if_needed()
                        page.locator(".gauge-block").screenshot(path=str(FIGURES_DIR / f"ui_v3_closeup_gauge_{theme}_{slug}_{w}.png"))

                    if state == "malicious" and w == 390:
                        page.locator(".why-block").scroll_into_view_if_needed()
                        page.locator(".why-block").screenshot(path=str(FIGURES_DIR / f"ui_v3_closeup_charts_{theme}_390.png"))
                        page.locator("#model").scroll_into_view_if_needed()
                        page.locator("#model").screenshot(path=str(FIGURES_DIR / f"ui_v3_closeup_model_{theme}_390.png"))

                    page.close()

        # Real file_input upload test: 3 synthetic PDFs -> 3 rows -> click row -> reloads result
        page = browser.new_page(viewport={"width": 1280, "height": 900})
        page.goto(f"{BASE_URL}/?theme=light", wait_until="domcontentloaded", timeout=60000)
        page.wait_for_selector("#model-info-panel .model-stats-grid", timeout=30000)
        for idx, fname in enumerate(["synthetic_a_minimal_blank.pdf", "synthetic_c_20_page_report.pdf", "synthetic_d_25_uris.pdf"], start=1):
            page.set_input_files("#file-input", str(SYNTH_DIR / fname))
            page.wait_for_function(f"document.querySelectorAll('#history-table-body tr').length === {idx}", timeout=30000)
        assert page.locator("#history-table-body .verdict-pill").count() == 3
        page.locator("#history-table-body tr").nth(2).click()
        assert page.locator("#detail-filename").inner_text() == "synthetic_a_minimal_blank.pdf"
        page.locator("#session-history").scroll_into_view_if_needed()
        page.locator("#session-history").screenshot(path=str(FIGURES_DIR / "ui_v3_section_history_3rows.png"))
        print("  [OK] History 3-row real upload + click-reload verified.")

        page.close()
        browser.close()
        print("\nALL GAUGE, TICKER, OVERFLOW, CHART-BAR & HISTORY CHECKS PASSED!")
finally:
    proc.kill()
    proc.wait()
