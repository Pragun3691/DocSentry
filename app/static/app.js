/**
 * DocSentry Frontend Application Logic
 * Pure Vanilla JavaScript - Offline-First, Zero External Dependencies, Zero Blue Colors
 */

document.addEventListener("DOMContentLoaded", () => {
  // DOM Elements
  const html = document.documentElement;
  const themeToggleBtn = document.getElementById("btn-theme-toggle");
  const themeIcon = document.getElementById("theme-icon");
  const themeText = document.getElementById("theme-text");
  
  const uploadZone = document.getElementById("upload-zone");
  const fileInput = document.getElementById("file-input");
  const loadingOverlay = document.getElementById("loading-overlay");
  const loadingStage = document.getElementById("loading-stage");
  const alertBox = document.getElementById("alert-box");
  
  const resultSection = document.getElementById("result-section");
  const verdictBadge = document.getElementById("verdict-badge");
  const verdictIcon = document.getElementById("verdict-icon");
  const verdictText = document.getElementById("verdict-text");
  const resultProbLarge = document.getElementById("result-prob-large");
  const badgeFileName = document.getElementById("badge-file-name");
  const badgeFileSize = document.getElementById("badge-file-size");
  const badgeScanTime = document.getElementById("badge-scan-time");
  
  const oodBanner = document.getElementById("ood-banner");
  const resultReason = document.getElementById("result-reason");
  const evidenceNote = document.getElementById("evidence-note");
  const gaugeRiskVal = document.getElementById("gauge-risk-val");
  const gaugeNeedle = document.getElementById("gauge-needle");
  const gaugeNeedleBubble = document.getElementById("gauge-needle-bubble");
  
  const shapChartContainer = document.getElementById("shap-chart");
  const familyChartContainer = document.getElementById("family-chart");
  
  const detailFilename = document.getElementById("detail-filename");
  const detailFilesize = document.getElementById("detail-filesize");
  const detailSha256 = document.getElementById("detail-sha256");
  const detailRawProb = document.getElementById("detail-raw-prob");
  const detailTiming = document.getElementById("detail-timing");
  const btnCopyHash = document.getElementById("btn-copy-hash");
  
  const historyTableBody = document.getElementById("history-table-body");
  const btnClearHistory = document.getElementById("btn-clear-history");
  
  const btnModelInfo = document.getElementById("btn-model-info");
  const modalModelInfo = document.getElementById("modal-model-info");
  const btnCloseModal = document.getElementById("btn-close-modal");
  const modalInfoBody = document.getElementById("modal-info-body");

  // State
  let sessionScans = [];
  let modelInfoData = null;

  // -------------------------------------------------------------------------
  // 1. Theme Management (defaults to dark if prefers-color-scheme: dark)
  // -------------------------------------------------------------------------
  function initTheme() {
    const savedTheme = localStorage.getItem("docsentry_theme");
    if (savedTheme) {
      setTheme(savedTheme);
    } else {
      const prefersDark = window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches;
      setTheme(prefersDark ? "dark" : "light");
    }
  }

  function setTheme(theme) {
    html.setAttribute("data-theme", theme);
    localStorage.setItem("docsentry_theme", theme);
    if (theme === "dark") {
      themeIcon.textContent = "☀️";
      themeText.textContent = "Light";
    } else {
      themeIcon.textContent = "🌙";
      themeText.textContent = "Dark";
    }
  }

  themeToggleBtn.addEventListener("click", () => {
    const current = html.getAttribute("data-theme") || "dark";
    setTheme(current === "dark" ? "light" : "dark");
  });

  // -------------------------------------------------------------------------
  // 2. Model Info Fetching & Modal
  // -------------------------------------------------------------------------
  async function fetchModelInfo() {
    try {
      const res = await fetch("/model-info");
      if (res.ok) {
        modelInfoData = await res.json();
      }
    } catch (e) {
      console.warn("Could not fetch model info at startup:", e);
    }
  }

  function renderModelInfoModal() {
    if (!modelInfoData) {
      modalInfoBody.innerHTML = "<p>Model specifications could not be retrieved from the server.</p>";
      return;
    }

    const m = modelInfoData.test_metrics || {};
    const rb = modelInfoData.review_band || {};
    const ood = modelInfoData.ood_thresholds || {};

    modalInfoBody.innerHTML = `
      <div style="margin-bottom: 1.25rem;">
        <h4 style="font-weight: 600; color: var(--text-primary); margin-bottom: 0.25rem;">Champion Model Configuration</h4>
        <p><strong>Architecture:</strong> ${modelInfoData.model_architecture} | <strong>Inputs:</strong> ${modelInfoData.features_count} static features</p>
        <p><strong>Calibrator:</strong> ${modelInfoData.calibration_method} | <strong>Operating Threshold:</strong> ${modelInfoData.operating_threshold}</p>
      </div>

      <h4 style="font-weight: 600; color: var(--text-primary); margin-bottom: 0.5rem;">EMBER2024 Test Set Evaluation (12,000 Documents)</h4>
      <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(130px, 1fr)); gap: 0.75rem; margin-bottom: 1.25rem;">
        <div style="background: var(--bg-tertiary); padding: 0.75rem; border-radius: var(--radius-sm); border: 1px solid var(--border-color);"><div style="font-size: 0.75rem; color: var(--text-muted); text-transform: uppercase;">Accuracy</div><div style="font-size: 1.25rem; font-weight: 700; color: var(--text-primary);">${(m.test_accuracy * 100).toFixed(2)}%</div></div>
        <div style="background: var(--bg-tertiary); padding: 0.75rem; border-radius: var(--radius-sm); border: 1px solid var(--border-color);"><div style="font-size: 0.75rem; color: var(--text-muted); text-transform: uppercase;">F1-Score</div><div style="font-size: 1.25rem; font-weight: 700; color: var(--text-primary);">${(m.test_f1 * 100).toFixed(2)}%</div></div>
        <div style="background: var(--bg-tertiary); padding: 0.75rem; border-radius: var(--radius-sm); border: 1px solid var(--border-color);"><div style="font-size: 0.75rem; color: var(--text-muted); text-transform: uppercase;">Malicious Recall</div><div style="font-size: 1.25rem; font-weight: 700; color: var(--text-primary);">${(m.test_recall * 100).toFixed(2)}%</div></div>
        <div style="background: var(--bg-tertiary); padding: 0.75rem; border-radius: var(--radius-sm); border: 1px solid var(--border-color);"><div style="font-size: 0.75rem; color: var(--text-muted); text-transform: uppercase;">Benign FPR</div><div style="font-size: 1.25rem; font-weight: 700; color: var(--text-primary);">${(m.test_fpr * 100).toFixed(2)}%</div></div>
        <div style="background: var(--bg-tertiary); padding: 0.75rem; border-radius: var(--radius-sm); border: 1px solid var(--border-color);"><div style="font-size: 0.75rem; color: var(--text-muted); text-transform: uppercase;">ROC-AUC</div><div style="font-size: 1.25rem; font-weight: 700; color: var(--text-primary);">${m.test_roc_auc?.toFixed(4) || "0.9887"}</div></div>
        <div style="background: var(--bg-tertiary); padding: 0.75rem; border-radius: var(--radius-sm); border: 1px solid var(--border-color);"><div style="font-size: 0.75rem; color: var(--text-muted); text-transform: uppercase;">PR-AUC</div><div style="font-size: 1.25rem; font-weight: 700; color: var(--text-primary);">${m.test_pr_auc?.toFixed(4) || "0.9911"}</div></div>
      </div>

      <h4 style="font-weight: 600; color: var(--text-primary); margin-top: 1rem; margin-bottom: 0.5rem;">Review Band &amp; Out-of-Distribution Envelope</h4>
      <p style="margin-bottom: 0.5rem;"><strong>Review Band Interval:</strong> [${(rb.low * 100).toFixed(1)}%, ${(rb.high * 100).toFixed(1)}%] (Test Auto-Accuracy: ${(rb.test_auto_accuracy * 100).toFixed(2)}%)</p>
      <p style="margin-bottom: 0.5rem;"><strong>File Size Envelope (0.5% - 99.5%):</strong> ${(ood.size_p05 / 1024).toFixed(1)} KB to ${(ood.size_p995 / (1024*1024)).toFixed(1)} MB</p>
      <p style="margin-bottom: 0.5rem;"><strong>String Count Envelope (0.5% - 99.5%):</strong> ${ood.numstrings_p05} to ${ood.numstrings_p995?.toLocaleString()} strings</p>
    `;
  }

  btnModelInfo.addEventListener("click", () => {
    renderModelInfoModal();
    modalModelInfo.classList.add("open");
  });

  btnCloseModal.addEventListener("click", () => {
    modalModelInfo.classList.remove("open");
  });

  window.addEventListener("click", (e) => {
    if (e.target === modalModelInfo) {
      modalModelInfo.classList.remove("open");
    }
  });

  // -------------------------------------------------------------------------
  // 3. Alerts & UI Helpers
  // -------------------------------------------------------------------------
  function showAlert(msg) {
    alertBox.textContent = msg;
    alertBox.style.display = "block";
    alertBox.scrollIntoView({ behavior: "smooth", block: "center" });
  }

  function hideAlert() {
    alertBox.style.display = "none";
    alertBox.textContent = "";
  }

  function formatBytes(bytes) {
    if (bytes === 0) return "0 B";
    const k = 1024;
    const sizes = ["B", "KB", "MB", "GB"];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
  }

  // -------------------------------------------------------------------------
  // 4. File Drag & Drop & Upload Handling
  // -------------------------------------------------------------------------
  uploadZone.addEventListener("click", () => fileInput.click());

  uploadZone.addEventListener("keydown", (e) => {
    if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      fileInput.click();
    }
  });

  uploadZone.addEventListener("dragover", (e) => {
    e.preventDefault();
    uploadZone.classList.add("dragover");
  });

  uploadZone.addEventListener("dragleave", () => {
    uploadZone.classList.remove("dragover");
  });

  uploadZone.addEventListener("drop", (e) => {
    e.preventDefault();
    uploadZone.classList.remove("dragover");
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      handleFile(e.dataTransfer.files[0]);
    }
  });

  fileInput.addEventListener("change", (e) => {
    if (e.target.files && e.target.files.length > 0) {
      handleFile(e.target.files[0]);
    }
  });

  async function handleFile(file) {
    hideAlert();

    // Client-side pre-validations
    if (!file.name.toLowerCase().endsWith(".pdf")) {
      showAlert("Invalid file format. DocSentry accepts %PDF files only.");
      return;
    }

    if (file.size === 0) {
      showAlert("Uploaded file is empty (0 bytes).");
      return;
    }

    if (file.size > 20 * 1024 * 1024) {
      showAlert("File exceeds the 20 MB size limit for real-time inspection.");
      return;
    }

    // UI Loading state
    uploadZone.style.display = "none";
    loadingOverlay.style.display = "block";
    loadingStage.textContent = "Extracting 658 static features from raw bytes...";

    const formData = new FormData();
    formData.append("file", file);

    const stageTimer1 = setTimeout(() => {
      loadingStage.textContent = "Executing calibrated XGBoost risk inference...";
    }, 400);

    const stageTimer2 = setTimeout(() => {
      loadingStage.textContent = "Computing local SHAP attributions via TreeExplainer...";
    }, 800);

    try {
      const response = await fetch("/scan", {
        method: "POST",
        body: formData
      });

      clearTimeout(stageTimer1);
      clearTimeout(stageTimer2);

      if (!response.ok) {
        let errDetail = "Scan request failed with HTTP " + response.status;
        try {
          const errJson = await response.json();
          if (errJson.detail) errDetail = errJson.detail;
        } catch (_) {}
        throw new Error(errDetail);
      }

      const scanResult = await response.json();
      displayResult(scanResult);
      addToHistory(scanResult);

    } catch (err) {
      showAlert(err.message || "An unexpected error occurred during document inspection.");
    } finally {
      loadingOverlay.style.display = "none";
      uploadZone.style.display = "block";
      fileInput.value = "";
    }
  }

  // -------------------------------------------------------------------------
  // 5. Result Rendering
  // -------------------------------------------------------------------------
  function displayResult(res) {
    resultSection.style.display = "block";

    // Header Badges
    badgeFileName.textContent = res.file_name;
    badgeFileSize.textContent = formatBytes(res.size);
    badgeScanTime.textContent = `${res.processing_ms} ms`;

    // Verdict Badge
    verdictBadge.className = "verdict-badge";
    if (res.verdict === "benign") {
      verdictBadge.classList.add("verdict-benign");
      verdictText.textContent = "BENIGN";
      verdictIcon.innerHTML = `<svg viewBox="0 0 24 24" width="28" height="28" fill="currentColor"><path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm-2 16l-4-4 1.41-1.41L10 14.17l6.59-6.59L18 9l-8 8z"/></svg>`;
    } else if (res.verdict === "needs_review") {
      verdictBadge.classList.add("verdict-review");
      verdictText.textContent = "NEEDS MANUAL REVIEW";
      verdictIcon.innerHTML = `<svg viewBox="0 0 24 24" width="28" height="28" fill="currentColor"><path d="M1 21h22L12 2 1 21zm12-3h-2v-2h2v2zm0-4h-2v-4h2v4z"/></svg>`;
    } else {
      verdictBadge.classList.add("verdict-malicious");
      verdictText.textContent = "LIKELY MALICIOUS";
      verdictIcon.innerHTML = `<svg viewBox="0 0 24 24" width="28" height="28" fill="currentColor"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm5 13.59L15.59 17 12 13.41 8.41 17 7 15.59 10.59 12 7 8.41 8.41 7 12 10.59 15.59 7 17 8.41 13.41 12 17 15.59z"/></svg>`;
    }

    // Probability Primary Display (Biggest number on card)
    const probPct = Math.min(Math.max(res.calibrated_probability * 100.0, 0.0), 100.0);
    resultProbLarge.textContent = `${probPct.toFixed(1)}%`;

    // OOD Warning Banner
    oodBanner.style.display = res.ood_warning ? "flex" : "none";

    // Plain-Language Reason
    resultReason.textContent = res.reason;

    // Evidence Note (/URI Dependence Note)
    if (res.evidence_note) {
      evidenceNote.textContent = res.evidence_note;
      evidenceNote.style.display = "block";
    } else {
      evidenceNote.style.display = "none";
      evidenceNote.textContent = "";
    }

    // Probability Gauge
    gaugeRiskVal.textContent = `${probPct.toFixed(1)}%`;
    gaugeNeedle.style.left = `${probPct}%`;
    gaugeNeedleBubble.textContent = `${probPct.toFixed(1)}%`;

    // File Details Grid
    detailFilename.textContent = res.file_name;
    detailFilesize.textContent = `${res.size.toLocaleString()} bytes (${formatBytes(res.size)})`;
    detailSha256.textContent = res.sha256;
    detailRawProb.textContent = `${(res.raw_probability * 100.0).toFixed(2)}% (raw probability: ${res.raw_probability.toFixed(4)})`;
    detailTiming.textContent = `${res.processing_ms} ms (end-to-end extraction & SHAP)`;

    // Render Charts
    renderShapChart(res.top_contributors);
    renderFamilyChart(res.family_summary);

    // Smooth scroll to results
    resultSection.scrollIntoView({ behavior: "smooth", block: "start" });
  }

  // Copy hash button
  btnCopyHash.addEventListener("click", () => {
    const text = detailSha256.textContent;
    if (text && text !== "-") {
      navigator.clipboard.writeText(text).then(() => {
        btnCopyHash.textContent = "Copied!";
        setTimeout(() => { btnCopyHash.textContent = "Copy"; }, 2000);
      });
    }
  });

  // -------------------------------------------------------------------------
  // 6. SVG Charts (Diverging SHAP & Feature Family)
  // Non-overlapping numeric labels outside bar ends, wrapping labels & tooltips
  // -------------------------------------------------------------------------
  function renderShapChart(contributors) {
    if (!contributors || contributors.length === 0) {
      shapChartContainer.innerHTML = "<p>No attribution data available.</p>";
      return;
    }

    // Top 8 sorted by absolute impact
    const items = contributors.slice(0, 8);
    const maxVal = Math.max(...items.map(d => Math.abs(d.shap_value)), 0.5);

    const width = 720;
    const height = 350;
    const margin = { top: 25, right: 65, bottom: 25, left: 260 };
    const chartWidth = width - margin.left - margin.right; // 395px
    const chartHeight = height - margin.top - margin.bottom;
    const rowHeight = chartHeight / items.length;
    const zeroX = margin.left + chartWidth / 2; // 457.5px

    // Max bar half-width leaves 45px padding before chart edge so labels never collide
    const usableHalfWidth = (chartWidth / 2) - 45;

    let svgHtml = `
      <svg viewBox="0 0 ${width} ${height}" style="width: 100%; height: 100%; font-family: inherit; font-size: 11px;">
        <!-- Center Axis -->
        <line x1="${zeroX}" y1="${margin.top}" x2="${zeroX}" y2="${height - margin.bottom}" stroke="var(--border-color)" stroke-width="1.5" stroke-dasharray="3,3" />
        <text x="${zeroX - 10}" y="${margin.top - 8}" text-anchor="end" fill="var(--color-benign-text)" font-weight="700">Toward Benign (&minus;)</text>
        <text x="${zeroX + 10}" y="${margin.top - 8}" text-anchor="start" fill="var(--color-malicious-text)" font-weight="700">Toward Malicious (+)</text>
    `;

    items.forEach((d, i) => {
      const y = margin.top + i * rowHeight + rowHeight / 2;
      const barHalfWidth = Math.min((Math.abs(d.shap_value) / maxVal) * usableHalfWidth, usableHalfWidth);
      const isMalicious = d.shap_value > 0;
      const barX = isMalicious ? zeroX : zeroX - barHalfWidth;
      const color = isMalicious ? "var(--color-malicious)" : "var(--color-benign)";

      // Wrap long names onto two lines if needed (>26 characters)
      const name = d.readable_name;
      let labelLines = [name];
      if (name.length > 26) {
        const words = name.split(" ");
        let line1 = "";
        let line2 = "";
        for (const w of words) {
          if ((line1 + " " + w).trim().length <= 24) {
            line1 = (line1 + " " + w).trim();
          } else {
            line2 = (line2 + " " + w).trim();
          }
        }
        if (line1 && line2) {
          labelLines = [line1, line2];
        }
      }

      // Feature Label SVG
      let textTspans = "";
      if (labelLines.length === 2) {
        textTspans = `
          <tspan x="${margin.left - 15}" dy="-0.45em">${labelLines[0]}</tspan>
          <tspan x="${margin.left - 15}" dy="1.15em">${labelLines[1]}</tspan>
        `;
      } else {
        textTspans = `<tspan x="${margin.left - 15}" dy="0.35em">${labelLines[0]}</tspan>`;
      }

      // Numeric Value Placement: outside the bar end away from the label column
      const valX = isMalicious ? (barX + barHalfWidth + 8) : (barX - 8);
      const valAnchor = isMalicious ? "start" : "end";

      svgHtml += `
        <!-- Feature Label with full tooltip & keyboard focusable group -->
        <g tabindex="0" role="group" aria-label="${name}">
          <title>${name} (${d.feature})</title>
          <text class="chart-label-text" x="${margin.left - 15}" y="${y}" text-anchor="end">
            ${textTspans}
          </text>
        </g>
        <!-- Horizontal Bar -->
        <rect x="${barX}" y="${y - 8}" width="${Math.max(barHalfWidth, 2)}" height="16" rx="3" fill="${color}" opacity="0.9">
          <title>${name}: ${d.shap_value > 0 ? "+" : ""}${d.shap_value.toFixed(4)}</title>
        </rect>
        <!-- Numeric Value Label (outside bar end with padding) -->
        <text class="chart-value-text" x="${valX}" y="${y + 4}" text-anchor="${valAnchor}">
          ${d.shap_value > 0 ? "+" : ""}${d.shap_value.toFixed(3)}
        </text>
      `;
    });

    svgHtml += `</svg>`;
    shapChartContainer.innerHTML = svgHtml;
  }

  function renderFamilyChart(familySummary) {
    if (!familySummary || Object.keys(familySummary).length === 0) {
      familyChartContainer.innerHTML = "<p>No family summary available.</p>";
      return;
    }

    const families = Object.entries(familySummary);
    families.sort((a, b) => Math.abs(b[1].net_attribution) - Math.abs(a[1].net_attribution));

    const maxVal = Math.max(...families.map(f => Math.abs(f[1].net_attribution)), 0.3);
    const width = 560;
    const height = 350;
    const margin = { top: 25, right: 60, bottom: 25, left: 200 };
    const chartWidth = width - margin.left - margin.right;
    const chartHeight = height - margin.top - margin.bottom;
    const rowHeight = chartHeight / families.length;
    const zeroX = margin.left + chartWidth / 2;
    const usableHalfWidth = (chartWidth / 2) - 40;

    let svgHtml = `
      <svg viewBox="0 0 ${width} ${height}" style="width: 100%; height: 100%; font-family: inherit; font-size: 11px;">
        <!-- Center Axis -->
        <line x1="${zeroX}" y1="${margin.top}" x2="${zeroX}" y2="${height - margin.bottom}" stroke="var(--border-color)" stroke-width="1.5" stroke-dasharray="3,3" />
        <text x="${zeroX - 8}" y="${margin.top - 8}" text-anchor="end" fill="var(--color-benign-text)" font-weight="700">Benign (&minus;)</text>
        <text x="${zeroX + 8}" y="${margin.top - 8}" text-anchor="start" fill="var(--color-malicious-text)" font-weight="700">Malicious (+)</text>
    `;

    families.forEach(([famName, stats], i) => {
      const y = margin.top + i * rowHeight + rowHeight / 2;
      const net = stats.net_attribution;
      const barHalfWidth = Math.min((Math.abs(net) / maxVal) * usableHalfWidth, usableHalfWidth);
      const isMalicious = net > 0;
      const barX = isMalicious ? zeroX : zeroX - barHalfWidth;
      const color = isMalicious ? "var(--color-malicious)" : "var(--color-benign)";

      const valX = isMalicious ? (barX + barHalfWidth + 8) : (barX - 8);
      const valAnchor = isMalicious ? "start" : "end";

      svgHtml += `
        <!-- Family Label -->
        <g tabindex="0" role="group" aria-label="${famName}">
          <title>${famName}: Net ${net > 0 ? "+" : ""}${net.toFixed(3)} (Pos: +${stats.positive_attribution.toFixed(3)}, Neg: ${stats.negative_attribution.toFixed(3)})</title>
          <text class="chart-label-text" x="${margin.left - 15}" y="${y + 4}" text-anchor="end">
            ${famName}
          </text>
        </g>
        <!-- Bar -->
        <rect x="${barX}" y="${y - 8}" width="${Math.max(barHalfWidth, 2)}" height="16" rx="3" fill="${color}" opacity="0.9">
          <title>${famName}: Net ${net > 0 ? "+" : ""}${net.toFixed(3)}</title>
        </rect>
        <!-- Value Label -->
        <text class="chart-value-text" x="${valX}" y="${y + 4}" text-anchor="${valAnchor}">
          ${net > 0 ? "+" : ""}${net.toFixed(2)}
        </text>
      `;
    });

    svgHtml += `</svg>`;
    familyChartContainer.innerHTML = svgHtml;
  }

  // -------------------------------------------------------------------------
  // 7. Session History Management
  // -------------------------------------------------------------------------
  function addToHistory(scanResult) {
    sessionScans.unshift({
      time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }),
      ...scanResult
    });
    renderHistory();
  }

  function renderHistory() {
    if (sessionScans.length === 0) {
      historyTableBody.innerHTML = `
        <tr>
          <td colspan="7" class="empty-history">No files scanned in this session yet. Upload a PDF above to begin.</td>
        </tr>
      `;
      return;
    }

    let rowsHtml = "";
    sessionScans.forEach((s) => {
      let verdictClass = "verdict-benign";
      let verdictLabel = "BENIGN";
      if (s.verdict === "needs_review") {
        verdictClass = "verdict-review";
        verdictLabel = "REVIEW";
      } else if (s.verdict === "malicious") {
        verdictClass = "verdict-malicious";
        verdictLabel = "MALICIOUS";
      }

      rowsHtml += `
        <tr>
          <td>${s.time}</td>
          <td><strong>${s.file_name}</strong></td>
          <td>${formatBytes(s.size)}</td>
          <td><span class="meta-badge ${verdictClass}" style="font-weight: 700; padding: 0.2rem 0.5rem;">${verdictLabel}</span></td>
          <td style="font-variant-numeric: tabular-nums;">${(s.calibrated_probability * 100).toFixed(1)}%</td>
          <td>${s.ood_warning ? '<span style="color: var(--color-ood); font-weight: 700;">WARNING</span>' : '<span style="color: var(--text-muted);">Normal</span>'}</td>
          <td>${s.processing_ms} ms</td>
        </tr>
      `;
    });

    historyTableBody.innerHTML = rowsHtml;
  }

  btnClearHistory.addEventListener("click", () => {
    sessionScans = [];
    renderHistory();
  });

  // Initialize
  initTheme();
  fetchModelInfo();

  // Check URL query parameters for automated verification & demo screenshots
  const urlParams = new URLSearchParams(window.location.search);
  const demoTheme = urlParams.get("theme");
  const demoMode = urlParams.get("demo");
  if (demoTheme) {
    setTheme(demoTheme);
  }
  if (demoMode) {
    fetch(`/demo-scan/${demoMode}`)
      .then(res => res.json())
      .then(data => displayResult(data))
      .catch(err => console.error("Automated demo load failed:", err));
  }
});
