/**
 * DocSentry Frontend Application Logic
 * Vanilla JS — Offline-First, Zero External Dependencies, Accessible
 */

document.addEventListener("DOMContentLoaded", () => {
  const html = document.documentElement;
  const themeToggleBtn = document.getElementById("btn-theme-toggle");
  const themeIcon = document.getElementById("theme-icon");
  const themeText = document.getElementById("theme-text");

  const uploadZone = document.getElementById("upload-zone");
  const fileInput = document.getElementById("file-input");
  const btnBrowse = document.getElementById("btn-browse");
  const sampleBtns = document.querySelectorAll(".sample-btn");
  const loadingOverlay = document.getElementById("loading-overlay");
  const loadingStage = document.getElementById("loading-stage");
  const alertBox = document.getElementById("alert-box");

  const resultSection = document.getElementById("result-section");
  const verdictBadge = document.getElementById("verdict-badge");
  const verdictIcon = document.getElementById("verdict-icon");
  const verdictText = document.getElementById("verdict-text");
  const resultProbLarge = document.getElementById("result-prob-large");
  const resultReason = document.getElementById("result-reason");
  const oodBanner = document.getElementById("ood-banner");
  const evidenceNote = document.getElementById("evidence-note");

  const gaugeRiskVal = document.getElementById("gauge-risk-val");
  const gaugeNeedle = document.getElementById("gauge-needle");
  const gaugeNeedleBubble = document.getElementById("gauge-needle-bubble");

  const shapChartContainer = document.getElementById("shap-chart");
  const shapTableSr = document.getElementById("shap-table-sr");
  const familyChartContainer = document.getElementById("family-chart");
  const familyTableSr = document.getElementById("family-table-sr");

  const detailFilename = document.getElementById("detail-filename");
  const detailFilesize = document.getElementById("detail-filesize");
  const detailSha256 = document.getElementById("detail-sha256");
  const detailRawProb = document.getElementById("detail-raw-prob");
  const detailTiming = document.getElementById("detail-timing");
  const btnCopyHash = document.getElementById("btn-copy-hash");

  const historyEmpty = document.getElementById("history-empty");
  const historyTableWrap = document.getElementById("history-table-wrap");
  const historyTableBody = document.getElementById("history-table-body");
  const btnClearHistory = document.getElementById("btn-clear-history");

  const modelInfoPanel = document.getElementById("model-info-panel");
  const modalModelCard = document.getElementById("modal-model-card");
  const modalMcBody = document.getElementById("modal-mc-body");
  const btnCloseMc = document.getElementById("btn-close-mc");

  let sessionScans = [];
  let modelInfoData = null;
  let lastContributors = null;
  let lastFamilySummary = null;
  let lastIsMobile = window.innerWidth < 640;

  // -------------------------------------------------------------------------
  // 1. Theme Management (Light default, saved localStorage toggle)
  // -------------------------------------------------------------------------
  function initTheme() {
    const savedTheme = localStorage.getItem("docsentry_theme") || "light";
    setTheme(savedTheme);
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
    const current = html.getAttribute("data-theme") || "light";
    setTheme(current === "dark" ? "light" : "dark");
  });

  // -------------------------------------------------------------------------
  // 2. Model Section (Populated dynamically from /model-info)
  // -------------------------------------------------------------------------
  async function fetchModelInfo() {
    try {
      const res = await fetch("/model-info");
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      modelInfoData = await res.json();
      renderModelSection(modelInfoData);
    } catch (err) {
      modelInfoPanel.innerHTML = `<p class="muted-mono">Could not load model metadata from /model-info.</p>`;
    }
  }

  function renderModelSection(data) {
    const m = data.test_metrics || {};
    const ci = data.bootstrap_95ci || {};
    const rb = data.review_band || {};
    const errs = data.error_counts || {};
    const valErr = errs.validation || {};
    const testErr = errs.test || {};
    const uri = data.uri_dependence || {};
    const uriMal0 = uri.malicious_uri_zero || {};

    modelInfoPanel.innerHTML = `
      <p><strong>Chosen Architecture:</strong> ${data.model_architecture} (${data.features_count} static features, ${data.calibration_method}, operating threshold ${data.operating_threshold})</p>
      <div class="model-stats-grid">
        <div class="model-stat-box">
          <div class="model-stat-k">Test F1 (95% CI)</div>
          <div class="model-stat-v">${ci.f1 || (m.test_f1 ? m.test_f1.toFixed(4) : "-")}</div>
        </div>
        <div class="model-stat-box">
          <div class="model-stat-k">Test Recall (95% CI)</div>
          <div class="model-stat-v">${ci.recall || (m.test_recall ? m.test_recall.toFixed(4) : "-")}</div>
        </div>
        <div class="model-stat-box">
          <div class="model-stat-k">Test FPR (95% CI)</div>
          <div class="model-stat-v">${ci.fpr || (m.test_fpr ? m.test_fpr.toFixed(4) : "-")}</div>
        </div>
        <div class="model-stat-box">
          <div class="model-stat-k">Review Band</div>
          <div class="model-stat-v">[${(rb.low * 100).toFixed(0)}%, ${(rb.high * 100).toFixed(0)}%]</div>
        </div>
        <div class="model-stat-box">
          <div class="model-stat-k">Test Review Rate</div>
          <div class="model-stat-v">${(rb.test_review_rate * 100).toFixed(2)}% (Auto-Acc ${(rb.test_auto_accuracy * 100).toFixed(2)}%)</div>
        </div>
        <div class="model-stat-box">
          <div class="model-stat-k">Errors at 0.4083</div>
          <div class="model-stat-v">Test: ${testErr.total ?? "-"} errors (${testErr.inside_band ?? "-"} inside the review band, ${testErr.outside_band ?? "-"} outside). Validation: ${valErr.total ?? "-"} (${valErr.inside_band ?? "-"} inside, ${valErr.outside_band ?? "-"} outside).</div>
        </div>
      </div>
      <p class="muted-mono" style="margin-bottom: 1rem;">
        /URI=0 malicious recall: ${uriMal0.recall_calibrated_pct || "-"} at calibrated threshold 0.4083 (${uriMal0.recall_pct || "-"} at default 0.50 threshold).
      </p>
      <button type="button" id="btn-open-mc" class="pill-btn pill-btn-sm">View Model Card (MODEL_CARD.md)</button>
    `;

    const btnOpenMc = document.getElementById("btn-open-mc");
    if (btnOpenMc) {
      btnOpenMc.addEventListener("click", () => {
        modalMcBody.textContent = data.model_card_markdown || "MODEL_CARD.md unavailable.";
        modalModelCard.classList.add("open");
      });
    }
  }

  btnCloseMc.addEventListener("click", () => modalModelCard.classList.remove("open"));
  window.addEventListener("click", (e) => {
    if (e.target === modalModelCard) modalModelCard.classList.remove("open");
  });

  // -------------------------------------------------------------------------
  // 3. Helpers & File Upload
  // -------------------------------------------------------------------------
  function showAlert(msg) {
    alertBox.textContent = msg;
    alertBox.style.display = "block";
  }

  function hideAlert() {
    alertBox.style.display = "none";
    alertBox.textContent = "";
  }

  function formatBytes(bytes) {
    if (bytes === 0) return "0 B";
    const k = 1000;
    const sizes = ["B", "KB", "MB", "GB"];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
  }

  btnBrowse.addEventListener("click", (e) => {
    e.stopPropagation();
    fileInput.click();
  });

  uploadZone.addEventListener("click", (e) => {
    if (e.target !== btnBrowse && e.target.tagName !== "LABEL") {
      fileInput.click();
    }
  });

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

  uploadZone.addEventListener("dragleave", () => uploadZone.classList.remove("dragover"));

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

  sampleBtns.forEach((btn) => {
    btn.addEventListener("click", async () => {
      const sampleType = btn.getAttribute("data-sample");
      hideAlert();
      uploadZone.style.display = "none";
      loadingOverlay.style.display = "block";
      loadingStage.textContent = `Running built-in synthetic sample (${sampleType})…`;
      try {
        const res = await fetch(`/demo-scan/${sampleType}`);
        if (!res.ok) throw new Error(`Sample scan failed (HTTP ${res.status})`);
        const data = await res.json();
        displayResult(data);
        addToHistory(data);
      } catch (err) {
        showAlert(err.message || "Sample scan failed.");
      } finally {
        loadingOverlay.style.display = "none";
        uploadZone.style.display = "block";
      }
    });
  });

  async function handleFile(file) {
    hideAlert();
    if (!file.name.toLowerCase().endsWith(".pdf")) {
      showAlert("Invalid file format. PDF files only.");
      return;
    }
    if (file.size === 0) {
      showAlert("Uploaded file is empty (0 bytes).");
      return;
    }
    if (file.size > 20 * 1024 * 1024) {
      showAlert("File exceeds the 20 MB size limit.");
      return;
    }

    uploadZone.style.display = "none";
    loadingOverlay.style.display = "block";
    loadingStage.textContent = "Extracting 658 static features from raw bytes…";

    const formData = new FormData();
    formData.append("file", file);

    try {
      const response = await fetch("/scan", { method: "POST", body: formData });
      if (!response.ok) {
        let errDetail = `Scan request failed (HTTP ${response.status})`;
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
      showAlert(err.message || "An unexpected error occurred during inspection.");
    } finally {
      loadingOverlay.style.display = "none";
      uploadZone.style.display = "block";
      fileInput.value = "";
    }
  }

  // -------------------------------------------------------------------------
  // 4. Result Sheet Rendering
  // -------------------------------------------------------------------------
  function getVerdictMeta(verdict) {
    if (verdict === "benign") {
      return {
        cls: "verdict-benign",
        text: "BENIGN",
        icon: `<svg viewBox="0 0 24 24" width="22" height="22" fill="currentColor"><path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm-2 16l-4-4 1.41-1.41L10 14.17l6.59-6.59L18 9l-8 8z"/></svg>`
      };
    }
    if (verdict === "needs_review") {
      return {
        cls: "verdict-review",
        text: "NEEDS MANUAL REVIEW",
        icon: `<svg viewBox="0 0 24 24" width="22" height="22" fill="currentColor"><path d="M1 21h22L12 2 1 21zm12-3h-2v-2h2v2zm0-4h-2v-4h2v4z"/></svg>`
      };
    }
    return {
      cls: "verdict-malicious",
      text: "LIKELY MALICIOUS",
      icon: `<svg viewBox="0 0 24 24" width="22" height="22" fill="currentColor"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm5 13.59L15.59 17 12 13.41 8.41 17 7 15.59 10.59 12 7 8.41 8.41 7 12 10.59 15.59 7 17 8.41 13.41 12 17 15.59z"/></svg>`
    };
  }

  function displayResult(res, shouldScroll = true) {
    resultSection.style.display = "block";

    const vMeta = getVerdictMeta(res.verdict);
    verdictBadge.className = `verdict-badge ${vMeta.cls}`;
    verdictIcon.innerHTML = vMeta.icon;
    verdictText.textContent = vMeta.text;

    const probPct = Math.min(Math.max(res.calibrated_probability * 100.0, 0.0), 100.0);
    resultProbLarge.textContent = `${probPct.toFixed(1)}%`;

    // Strip redundant OOD notice from reason string in UI (OUT OF RANGE banner handles it)
    const cleanReason = (res.reason || "").replace(/\s*\[Notice:[^\]]*\]/g, "").trim();
    resultReason.textContent = cleanReason;

    oodBanner.style.display = res.ood_warning ? "flex" : "none";
    const oodBannerText = document.getElementById("ood-banner-text");
    if (oodBannerText) {
      let rangeInfo = " (training files: 358 B to 30.6 MB, 17 to 181,975 extracted strings)";
      if (modelInfoData && modelInfoData.ood_thresholds) {
        const ood = modelInfoData.ood_thresholds;
        rangeInfo = ` (training files: ${formatBytes(ood.size_p05)} to ${formatBytes(ood.size_p995)}, ${Math.round(ood.numstrings_p05)} to ${Math.round(ood.numstrings_p995).toLocaleString()} extracted strings)`;
      }
      oodBannerText.textContent = `This file's size or text content is outside the range of the files the model was trained on${rangeInfo}. Treat the score with extra caution.`;
    }

    if (res.evidence_note) {
      evidenceNote.textContent = res.evidence_note;
      evidenceNote.style.display = "flex";
    } else {
      evidenceNote.style.display = "none";
      evidenceNote.textContent = "";
    }

    gaugeRiskVal.textContent = `${probPct.toFixed(1)}%`;
    gaugeNeedle.style.left = `${probPct}%`;
    gaugeNeedleBubble.textContent = `Needle: ${probPct.toFixed(1)}%`;

    detailFilename.textContent = res.file_name;
    detailFilesize.textContent = `${res.size.toLocaleString()} bytes (${formatBytes(res.size)})`;
    detailSha256.textContent = res.sha256;
    detailRawProb.textContent = `${(res.raw_probability * 100.0).toFixed(2)}% (raw: ${res.raw_probability.toFixed(4)})`;
    detailTiming.textContent = `${res.processing_ms} ms (static extraction & SHAP)`;

    renderShapChart(res.top_contributors);
    renderFamilyChart(res.family_summary);

    if (shouldScroll) {
      resultSection.scrollIntoView({ behavior: "smooth", block: "start" });
    }
  }

  btnCopyHash.addEventListener("click", async () => {
    const text = detailSha256.textContent;
    if (!text || text === "-") return;
    try {
      if (navigator.clipboard && navigator.clipboard.writeText) {
        await navigator.clipboard.writeText(text);
      } else {
        throw new Error("Clipboard API unavailable");
      }
      btnCopyHash.textContent = "Copied!";
    } catch (_) {
      btnCopyHash.textContent = "Copy failed";
    }
    setTimeout(() => { btnCopyHash.textContent = "Copy"; }, 2000);
  });

  // -------------------------------------------------------------------------
  // 5. Full-Width Diverging SVG Charts + Visually Hidden Accessible Tables
  // -------------------------------------------------------------------------
  function wrapTwoLines(text, maxChars) {
    if (text.length <= maxChars) return [text];
    const words = text.split(" ");
    let l1 = "";
    let l2 = "";
    for (const w of words) {
      if ((l1 + " " + w).trim().length <= maxChars) {
        l1 = (l1 + " " + w).trim();
      } else {
        l2 = (l2 + " " + w).trim();
      }
    }
    return l1 && l2 ? [l1, l2] : [text];
  }

  function renderShapChart(contributors) {
    lastContributors = contributors;
    if (!contributors || contributors.length === 0) {
      shapChartContainer.innerHTML = "<p>No attribution data available.</p>";
      shapTableSr.innerHTML = "";
      return;
    }

    const items = contributors.slice(0, 8);
    const maxVal = Math.max(...items.map(d => Math.abs(d.shap_value)), 0.5);
    const isMobile = window.innerWidth < 640;

    let svg = "";
    let srRows = "";

    if (isMobile) {
      const width = 340;
      const rowHeight = 62;
      const margin = { top: 32, right: 12, bottom: 14, left: 12 };
      const height = margin.top + items.length * rowHeight + margin.bottom;
      const zeroX = width / 2;
      const usableHalf = (width / 2) - 66; // room for value label at end of bar inside 340px

      svg = `
        <svg viewBox="0 0 ${width} ${height}" style="width: 100%; height: auto;" role="img" aria-label="Diverging bar chart of top 8 contributing features">
          <text class="chart-svg-axis-label" x="${zeroX - 6}" y="18" text-anchor="end" fill="var(--verdict-benign)" style="font-size:11px;">&larr; benign</text>
          <text class="chart-svg-axis-label" x="${zeroX + 6}" y="18" text-anchor="start" fill="var(--verdict-malicious)" style="font-size:11px;">malicious &rarr;</text>
          <line x1="${zeroX}" y1="${margin.top}" x2="${zeroX}" y2="${height - margin.bottom}" stroke="var(--ink)" stroke-width="1.5" stroke-dasharray="4,4" />
      `;

      items.forEach((d, i) => {
        const rowTop = margin.top + i * rowHeight;
        const barW = Math.max(Math.min((Math.abs(d.shap_value) / maxVal) * usableHalf, usableHalf), 6);
        const isMal = d.shap_value > 0;
        const barX = isMal ? zeroX : zeroX - barW;
        const barY = rowTop + 28;
        const color = isMal ? "var(--verdict-malicious)" : "var(--verdict-benign)";
        const valX = isMal ? (barX + barW + 6) : (barX - 6);
        const valAnchor = isMal ? "start" : "end";
        const valText = `${isMal ? "+" : ""}${d.shap_value.toFixed(3)}`;
        const tipText = d.note ? `${d.readable_name} (${d.note})` : `${d.readable_name} (${d.feature})`;

        const lines = wrapTwoLines(d.readable_name, 38);
        const tspans = lines.length === 2
          ? `<tspan x="${margin.left}" dy="0">${lines[0]}</tspan><tspan x="${margin.left}" dy="1.15em">${lines[1]}</tspan>`
          : `<tspan x="${margin.left}" dy="0">${lines[0]}</tspan>`;

        svg += `
          <g class="chart-row" tabindex="0" aria-label="${tipText}: ${valText}">
            <title>${tipText}: ${valText}</title>
            <text class="chart-svg-label" x="${margin.left}" y="${rowTop + 12}" text-anchor="start" style="font-size:11.5px;">${tspans}</text>
            <rect class="chart-bar" x="${barX}" y="${barY}" width="${barW}" height="16" rx="3" fill="${color}" />
            <text class="chart-svg-value" x="${valX}" y="${barY + 12}" text-anchor="${valAnchor}" style="font-size:11.5px;">${valText}</text>
          </g>
        `;
        srRows += `<tr><td>${d.readable_name}</td><td>${valText}</td><td>${d.direction}</td></tr>`;
      });
    } else {
      const width = 920;
      const rowHeight = 46;
      const margin = { top: 34, right: 90, bottom: 20, left: 320 };
      const height = margin.top + items.length * rowHeight + margin.bottom;
      const chartWidth = width - margin.left - margin.right;
      const zeroX = margin.left + chartWidth / 2;
      const usableHalf = (chartWidth / 2) - 70;

      svg = `
        <svg viewBox="0 0 ${width} ${height}" style="width: 100%; min-width: 680px; height: auto;" role="img" aria-label="Diverging bar chart of top 8 contributing features">
          <line x1="${zeroX}" y1="${margin.top}" x2="${zeroX}" y2="${height - margin.bottom}" stroke="var(--ink)" stroke-width="1.5" stroke-dasharray="4,4" />
          <text class="chart-svg-axis-label" x="${zeroX - 10}" y="20" text-anchor="end" fill="var(--verdict-benign)">&larr; pushes toward benign</text>
          <text class="chart-svg-axis-label" x="${zeroX + 10}" y="20" text-anchor="start" fill="var(--verdict-malicious)">pushes toward malicious &rarr;</text>
      `;

      items.forEach((d, i) => {
        const y = margin.top + i * rowHeight + rowHeight / 2;
        const barW = Math.max(Math.min((Math.abs(d.shap_value) / maxVal) * usableHalf, usableHalf), 6);
        const isMal = d.shap_value > 0;
        const barX = isMal ? zeroX : zeroX - barW;
        const color = isMal ? "var(--verdict-malicious)" : "var(--verdict-benign)";
        const valX = isMal ? (barX + barW + 10) : (barX - 10);
        const valAnchor = isMal ? "start" : "end";
        const valText = `${isMal ? "+" : ""}${d.shap_value.toFixed(3)}`;

        const lines = wrapTwoLines(d.readable_name, 30);
        const tspans = lines.length === 2
          ? `<tspan x="${margin.left - 16}" dy="-0.4em">${lines[0]}</tspan><tspan x="${margin.left - 16}" dy="1.2em">${lines[1]}</tspan>`
          : `<tspan x="${margin.left - 16}" dy="0.35em">${lines[0]}</tspan>`;

        const tipText = d.note ? `${d.readable_name} (${d.note})` : `${d.readable_name} (${d.feature})`;

        svg += `
          <g class="chart-row" tabindex="0" aria-label="${tipText}: ${valText}">
            <title>${tipText}: ${valText}</title>
            <text class="chart-svg-label" x="${margin.left - 16}" y="${y}" text-anchor="end">${tspans}</text>
            <rect class="chart-bar" x="${barX}" y="${y - 10}" width="${barW}" height="20" rx="3" fill="${color}" />
            <text class="chart-svg-value" x="${valX}" y="${y + 5}" text-anchor="${valAnchor}">${valText}</text>
          </g>
        `;
        srRows += `<tr><td>${d.readable_name}</td><td>${valText}</td><td>${d.direction}</td></tr>`;
      });
    }

    svg += `</svg>`;
    shapChartContainer.innerHTML = svg;
    shapTableSr.innerHTML = `<table><caption>Top 8 SHAP Contributors</caption><thead><tr><th>Feature</th><th>SHAP</th><th>Direction</th></tr></thead><tbody>${srRows}</tbody></table>`;
  }

  function renderFamilyChart(familySummary) {
    lastFamilySummary = familySummary;
    if (!familySummary || Object.keys(familySummary).length === 0) {
      familyChartContainer.innerHTML = "<p>No family summary available.</p>";
      familyTableSr.innerHTML = "";
      return;
    }

    const families = Object.entries(familySummary).sort((a, b) => Math.abs(b[1].net_attribution) - Math.abs(a[1].net_attribution));
    const maxVal = Math.max(...families.map(f => Math.abs(f[1].net_attribution)), 0.3);
    const isMobile = window.innerWidth < 640;

    let svg = "";
    let srRows = "";

    if (isMobile) {
      const width = 340;
      const rowHeight = 52;
      const margin = { top: 32, right: 12, bottom: 14, left: 12 };
      const height = margin.top + families.length * rowHeight + margin.bottom;
      const zeroX = width / 2;
      const usableHalf = (width / 2) - 66;

      svg = `
        <svg viewBox="0 0 ${width} ${height}" style="width: 100%; height: auto;" role="img" aria-label="Diverging bar chart of feature family net attributions">
          <text class="chart-svg-axis-label" x="${zeroX - 6}" y="18" text-anchor="end" fill="var(--verdict-benign)" style="font-size:11px;">&larr; benign</text>
          <text class="chart-svg-axis-label" x="${zeroX + 6}" y="18" text-anchor="start" fill="var(--verdict-malicious)" style="font-size:11px;">malicious &rarr;</text>
          <line x1="${zeroX}" y1="${margin.top}" x2="${zeroX}" y2="${height - margin.bottom}" stroke="var(--ink)" stroke-width="1.5" stroke-dasharray="4,4" />
      `;

      families.forEach(([famName, stats], i) => {
        const rowTop = margin.top + i * rowHeight;
        const net = stats.net_attribution;
        const barW = Math.max(Math.min((Math.abs(net) / maxVal) * usableHalf, usableHalf), 6);
        const isMal = net > 0;
        const barX = isMal ? zeroX : zeroX - barW;
        const barY = rowTop + 20;
        const color = isMal ? "var(--verdict-malicious)" : "var(--verdict-benign)";
        const valX = isMal ? (barX + barW + 6) : (barX - 6);
        const valAnchor = isMal ? "start" : "end";
        const valText = `${isMal ? "+" : ""}${net.toFixed(2)}`;

        svg += `
          <g class="chart-row" tabindex="0" aria-label="${famName}: ${valText}">
            <title>${famName}: Net ${valText}</title>
            <text class="chart-svg-label" x="${margin.left}" y="${rowTop + 12}" text-anchor="start" style="font-size:11.5px;">${famName}</text>
            <rect class="chart-bar" x="${barX}" y="${barY}" width="${barW}" height="16" rx="3" fill="${color}" />
            <text class="chart-svg-value" x="${valX}" y="${barY + 12}" text-anchor="${valAnchor}" style="font-size:11.5px;">${valText}</text>
          </g>
        `;
        srRows += `<tr><td>${famName}</td><td>${valText}</td></tr>`;
      });
    } else {
      const width = 920;
      const rowHeight = 42;
      const margin = { top: 34, right: 90, bottom: 20, left: 320 };
      const height = margin.top + families.length * rowHeight + margin.bottom;
      const chartWidth = width - margin.left - margin.right;
      const zeroX = margin.left + chartWidth / 2;
      const usableHalf = (chartWidth / 2) - 70;

      svg = `
        <svg viewBox="0 0 ${width} ${height}" style="width: 100%; min-width: 680px; height: auto;" role="img" aria-label="Diverging bar chart of feature family net attributions">
          <line x1="${zeroX}" y1="${margin.top}" x2="${zeroX}" y2="${height - margin.bottom}" stroke="var(--ink)" stroke-width="1.5" stroke-dasharray="4,4" />
          <text class="chart-svg-axis-label" x="${zeroX - 10}" y="20" text-anchor="end" fill="var(--verdict-benign)">&larr; pushes toward benign</text>
          <text class="chart-svg-axis-label" x="${zeroX + 10}" y="20" text-anchor="start" fill="var(--verdict-malicious)">pushes toward malicious &rarr;</text>
      `;

      families.forEach(([famName, stats], i) => {
        const y = margin.top + i * rowHeight + rowHeight / 2;
        const net = stats.net_attribution;
        const barW = Math.max(Math.min((Math.abs(net) / maxVal) * usableHalf, usableHalf), 6);
        const isMal = net > 0;
        const barX = isMal ? zeroX : zeroX - barW;
        const color = isMal ? "var(--verdict-malicious)" : "var(--verdict-benign)";
        const valX = isMal ? (barX + barW + 10) : (barX - 10);
        const valAnchor = isMal ? "start" : "end";
        const valText = `${isMal ? "+" : ""}${net.toFixed(2)}`;

        svg += `
          <g class="chart-row" tabindex="0" aria-label="${famName}: ${valText}">
            <title>${famName}: Net ${valText}</title>
            <text class="chart-svg-label" x="${margin.left - 16}" y="${y + 5}" text-anchor="end">${famName}</text>
            <rect class="chart-bar" x="${barX}" y="${y - 10}" width="${barW}" height="20" rx="3" fill="${color}" />
            <text class="chart-svg-value" x="${valX}" y="${y + 5}" text-anchor="${valAnchor}">${valText}</text>
          </g>
        `;
        srRows += `<tr><td>${famName}</td><td>${valText}</td></tr>`;
      });
    }

    svg += `</svg>`;
    familyChartContainer.innerHTML = svg;
    familyTableSr.innerHTML = `<table><caption>Feature Family Net Attribution</caption><thead><tr><th>Family</th><th>Net SHAP</th></tr></thead><tbody>${srRows}</tbody></table>`;
  }

  let resizeTimer = null;
  window.addEventListener("resize", () => {
    clearTimeout(resizeTimer);
    resizeTimer = setTimeout(() => {
      const nowMobile = window.innerWidth < 640;
      if (nowMobile !== lastIsMobile) {
        lastIsMobile = nowMobile;
        if (lastContributors) renderShapChart(lastContributors);
        if (lastFamilySummary) renderFamilyChart(lastFamilySummary);
      }
    }, 100);
  });

  // -------------------------------------------------------------------------
  // 6. Session History (Clickable rows reload report sheet)
  // -------------------------------------------------------------------------
  function addToHistory(scanResult) {
    sessionScans.unshift({
      time: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" }),
      result: scanResult
    });
    renderHistory();
  }

  function renderHistory() {
    if (sessionScans.length === 0) {
      historyEmpty.style.display = "block";
      historyTableWrap.style.display = "none";
      historyTableBody.innerHTML = "";
      return;
    }

    historyEmpty.style.display = "none";
    historyTableWrap.style.display = "block";

    historyTableBody.innerHTML = "";
    sessionScans.forEach((entry) => {
      const s = entry.result;
      const vMeta = getVerdictMeta(s.verdict);
      const tr = document.createElement("tr");
      tr.className = "history-row";
      tr.tabIndex = 0;
      tr.setAttribute("aria-label", `Reload scan result for ${s.file_name}`);

      tr.innerHTML = `
        <td>${entry.time}</td>
        <td><strong>${s.file_name}</strong></td>
        <td>${formatBytes(s.size)}</td>
        <td><span class="verdict-pill ${vMeta.cls}">${vMeta.icon} ${vMeta.text}</span></td>
        <td>${(s.calibrated_probability * 100).toFixed(1)}%</td>
        <td>${s.ood_warning ? "OUT OF RANGE" : "Normal"}</td>
        <td>${s.processing_ms} ms</td>
      `;

      const reloadFn = () => displayResult(s, true);
      tr.addEventListener("click", reloadFn);
      tr.addEventListener("keydown", (e) => {
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          reloadFn();
        }
      });
      historyTableBody.appendChild(tr);
    });
  }

  btnClearHistory.addEventListener("click", () => {
    sessionScans = [];
    renderHistory();
  });

  // Initialize
  initTheme();
  fetchModelInfo();

  // Automated screenshot / demo query parameter handling
  const urlParams = new URLSearchParams(window.location.search);
  const demoTheme = urlParams.get("theme");
  const demoMode = urlParams.get("demo");
  if (demoTheme) setTheme(demoTheme);
  if (demoMode) {
    fetch(`/demo-scan/${demoMode}`)
      .then(res => res.json())
      .then(data => displayResult(data, false))
      .catch(err => console.error("Demo load failed:", err));
  }
});
