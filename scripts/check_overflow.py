import sys
import time
import subprocess
import urllib.request
from playwright.sync_api import sync_playwright

CHROME = r"C:\Program Files\Google\Chrome\Application\chrome.exe"
PORT = 8013
proc = subprocess.Popen(
    [sys.executable, "-m", "uvicorn", "app.main:app", "--port", str(PORT), "--host", "127.0.0.1"],
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL,
)

for _ in range(30):
    try:
        if urllib.request.urlopen(f"http://127.0.0.1:{PORT}/health", timeout=1).status == 200:
            break
    except Exception:
        time.sleep(0.5)

try:
    with sync_playwright() as p:
        browser = p.chromium.launch(executable_path=CHROME, headless=True)
        for theme in ["light", "dark"]:
            for w in [360, 390, 768, 1280]:
                for state in ["", "benign", "review", "malicious", "ood"]:
                    q = f"?theme={theme}" + (f"&demo={state}" if state else "")
                    page = browser.new_page(viewport={"width": w, "height": 900})
                    page.goto(f"http://127.0.0.1:{PORT}/{q}", wait_until="networkidle")
                    if state:
                        page.wait_for_function("document.getElementById('result-section').style.display === 'block'", timeout=5000)
                    res = page.evaluate("""() => {
                        const sw = document.documentElement.scrollWidth;
                        const cw = document.documentElement.clientWidth;
                        const bad = [];
                        for (const el of document.querySelectorAll('*')) {
                            const r = el.getBoundingClientRect();
                            if (r.width > 0 && r.right > cw + 1) {
                                if (!el.closest('.chart-scroll-box') && !el.closest('.table-scroll-box') && !el.closest('.ticker-strip')) {
                                    bad.push({
                                        tag: el.tagName,
                                        id: el.id || '',
                                        cls: typeof el.className === 'string' ? el.className : '',
                                        right: Math.round(r.right),
                                        cw: cw
                                    });
                                }
                            }
                        }
                        return {sw, cw, bad: bad.slice(0, 10)};
                    }""")
                    status = "OK" if res["sw"] <= res["cw"] and len(res["bad"]) == 0 else "FAIL"
                    print(f"[{status}] theme={theme:<5} width={w:<4} state={state or 'empty':<9} scrollWidth={res['sw']} clientWidth={res['cw']} bad={len(res['bad'])}")
                    for b in res["bad"]:
                        print("   OVERFLOW:", b)
                    page.close()
        browser.close()
finally:
    proc.kill()
    proc.wait()
