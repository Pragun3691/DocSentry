import os
import sys
import time
import subprocess
import urllib.request
from pathlib import Path

CHROME_PATH = r"C:\Program Files\Google\Chrome\Application\chrome.exe"
if not Path(CHROME_PATH).exists():
    print(f"Error: Chrome not found at {CHROME_PATH}")
    sys.exit(1)

BASE_DIR = Path(__file__).resolve().parent.parent
FIGURES_DIR = BASE_DIR / "reports/figures"
FIGURES_DIR.mkdir(parents=True, exist_ok=True)

PORT = 8008
BASE_URL = f"http://127.0.0.1:{PORT}"

print(f"Starting DocSentry FastAPI server on port {PORT} for screenshot capture...")
server_process = subprocess.Popen(
    [sys.executable, "-m", "uvicorn", "app.main:app", "--port", str(PORT), "--host", "127.0.0.1"],
    cwd=str(BASE_DIR),
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL
)

# Wait for server to be responsive
ready = False
for _ in range(30):
    try:
        with urllib.request.urlopen(f"{BASE_URL}/health", timeout=1) as resp:
            if resp.status == 200:
                ready = True
                break
    except Exception:
        time.sleep(0.5)

if not ready:
    print("Error: FastAPI server failed to start within 15 seconds.")
    server_process.kill()
    sys.exit(1)

print("FastAPI server is UP. Commencing headless browser screenshot capture...")

# Screenshot Tasks
tasks = [
    # Part 1, Item 4: General feature screenshots & responsive checks
    ("ui_benign.png", "?demo=benign&theme=dark", 1280, 950),
    ("ui_needs_review.png", "?demo=review&theme=dark", 1280, 950),
    ("ui_malicious.png", "?demo=malicious&theme=dark", 1280, 950),
    ("ui_ood_warning.png", "?demo=ood&theme=dark", 1280, 950),
    ("ui_1280px.png", "?demo=review&theme=dark", 1280, 900),
    ("ui_768px.png", "?demo=review&theme=dark", 768, 1024),
    ("ui_390px.png", "?demo=review&theme=dark", 390, 844),

    # Part 1b, Item 11: Both themes at 1280px and 390px for benign, review, malicious, and ood (synthetic PDFs only)
    ("ui_dark_benign_1280.png", "?demo=benign&theme=dark", 1280, 900),
    ("ui_dark_benign_390.png", "?demo=benign&theme=dark", 390, 844),
    ("ui_dark_review_1280.png", "?demo=review&theme=dark", 1280, 900),
    ("ui_dark_review_390.png", "?demo=review&theme=dark", 390, 844),
    ("ui_dark_malicious_1280.png", "?demo=malicious&theme=dark", 1280, 900),
    ("ui_dark_malicious_390.png", "?demo=malicious&theme=dark", 390, 844),
    ("ui_dark_ood_1280.png", "?demo=ood&theme=dark", 1280, 900),
    ("ui_dark_ood_390.png", "?demo=ood&theme=dark", 390, 844),

    ("ui_light_benign_1280.png", "?demo=benign&theme=light", 1280, 900),
    ("ui_light_benign_390.png", "?demo=benign&theme=light", 390, 844),
    ("ui_light_review_1280.png", "?demo=review&theme=light", 1280, 900),
    ("ui_light_review_390.png", "?demo=review&theme=light", 390, 844),
    ("ui_light_malicious_1280.png", "?demo=malicious&theme=light", 1280, 900),
    ("ui_light_malicious_390.png", "?demo=malicious&theme=light", 390, 844),
    ("ui_light_ood_1280.png", "?demo=ood&theme=light", 1280, 900),
    ("ui_light_ood_390.png", "?demo=ood&theme=light", 390, 844),
]

try:
    for filename, query, w, h in tasks:
        out_path = FIGURES_DIR / filename
        url = f"{BASE_URL}/{query}"
        cmd = [
            CHROME_PATH,
            "--headless",
            "--disable-gpu",
            "--no-sandbox",
            f"--window-size={w},{h}",
            "--virtual-time-budget=2000",
            f"--screenshot={str(out_path)}",
            url
        ]
        res = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if out_path.exists() and out_path.stat().st_size > 0:
            print(f"  [+] Saved ({w}x{h}): {filename} ({out_path.stat().st_size:,} bytes)")
        else:
            print(f"  [-] Failed to capture: {filename}")
finally:
    print("Shutting down screenshot FastAPI server...")
    server_process.kill()
    server_process.wait()
    print("All screenshot processes finished.")
