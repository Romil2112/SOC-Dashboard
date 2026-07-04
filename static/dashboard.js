// SOC Dashboard — alert queue + live stats with interactive filters.
"use strict";

const REFRESH_MS = 30000;

const CATEGORY_COLORS = {
  brute_force: "#ef4444",
  malware:     "#f97316",
  phishing:    "#eab308",
  port_scan:   "#3b82f6",
  anomaly:     "#8b5cf6",
};

const SEVERITY_COLORS = {
  CRITICAL: "#ef4444",
  HIGH:     "#f97316",
  MEDIUM:   "#eab308",
  LOW:      "#22c55e",
};

const SEVERITY_BADGE = {
  CRITICAL: "text-bg-danger",
  HIGH:     "text-bg-warning",
  MEDIUM:   "text-bg-info",
  LOW:      "text-bg-success",
};

// Palette cycled through for the (open-ended) detection-source dimension.
const SOURCE_PALETTE = ["#3b82f6", "#22c55e", "#eab308", "#f97316", "#8b5cf6",
                        "#ec4899", "#14b8a6", "#64748b"];

let categoryChart, severityChart, sourceChart;

// ----- filters -------------------------------------------------------------- //
// Live filter state read from the three <select> controls. Empty string = "all".
function currentFilters() {
  return {
    severity:    (document.getElementById("filter-severity")?.value || "").trim(),
    source:      (document.getElementById("filter-source")?.value || "").trim(),
    assigned_to: (document.getElementById("filter-assignee")?.value || "").trim(),
  };
}

function filterQuery() {
  const f = currentFilters();
  const qs = new URLSearchParams();
  if (f.severity) qs.set("severity", f.severity);
  if (f.source) qs.set("source", f.source);
  if (f.assigned_to) qs.set("assigned_to", f.assigned_to);
  const s = qs.toString();
  return s ? `?${s}` : "";
}

// Populate the source/assignee dropdowns from /api/stats, preserving selection.
function syncFilterOptions(stats) {
  fillSelect("filter-source", Object.keys(stats.by_source || {}).sort());
  fillSelect("filter-assignee", stats.assignees || []);
}

function fillSelect(id, values) {
  const el = document.getElementById(id);
  if (!el) return;
  const current = el.value;
  const placeholder = el.options[0] ? el.options[0].outerHTML : "";
  el.innerHTML = placeholder + values
    .map(v => `<option value="${escapeHtml(v)}">${escapeHtml(v)}</option>`)
    .join("");
  if (values.includes(current)) el.value = current;
}

// ----- analyst name (localStorage) ----------------------------------------- //
function getAnalyst() {
  return localStorage.getItem("soc_analyst") || "";
}

function initAnalystInput() {
  const input = document.getElementById("analyst-name");
  if (!input) return;
  input.value = getAnalyst();
  input.addEventListener("input", () => {
    localStorage.setItem("soc_analyst", input.value.trim());
  });
}

// ----- helpers ------------------------------------------------------------- //
function ageString(iso) {
  const created = new Date(iso);
  const secs = Math.max(0, (Date.now() - created.getTime()) / 1000);
  const mins = Math.floor(secs / 60);
  if (mins < 60) return `${mins}m`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ${mins % 60}m`;
  const days = Math.floor(hrs / 24);
  return `${days}d ${hrs % 24}h`;
}

function setStatus(text) {
  const el = document.getElementById("refresh-status");
  if (el) el.textContent = text;
}

// ----- alerts -------------------------------------------------------------- //
async function loadAlerts() {
  const res = await fetch("/api/alerts" + filterQuery());
  const alerts = await res.json();
  const tbody = document.getElementById("alert-rows");
  if (!tbody) return;

  if (!alerts.length) {
    tbody.innerHTML =
      `<tr><td colspan="7" class="text-center text-secondary">No matching open alerts 🎉</td></tr>`;
    return;
  }

  tbody.innerHTML = alerts.map(a => `
    <tr data-id="${a.id}">
      <td><span class="badge sev-badge ${SEVERITY_BADGE[a.severity] || "text-bg-secondary"}">${a.severity}</span></td>
      <td>${escapeHtml(a.title)}</td>
      <td><span class="text-capitalize">${a.category.replace("_", " ")}</span></td>
      <td>${escapeHtml(a.source || "—")}</td>
      <td><code>${escapeHtml(a.source_ip || "")}</code></td>
      <td>${ageString(a.created_at)}</td>
      <td class="text-end">
        <button class="btn btn-sm btn-outline-success"  onclick="classifyAlert(${a.id}, 'classify_tp')">TP</button>
        <button class="btn btn-sm btn-outline-secondary" onclick="classifyAlert(${a.id}, 'classify_fp')">FP</button>
        <button class="btn btn-sm btn-outline-danger"   onclick="classifyAlert(${a.id}, 'escalate')">Escalate</button>
      </td>
    </tr>`).join("");
}

async function classifyAlert(id, action) {
  const analyst = getAnalyst();
  if (!analyst) {
    alert("Enter your analyst name first (top-right of the queue).");
    const input = document.getElementById("analyst-name");
    if (input) input.focus();
    return;
  }
  const csrfToken = document.querySelector('meta[name="csrf-token"]')?.content || "";
  const res = await fetch(`/api/alerts/${id}/classify`, {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-CSRFToken": csrfToken },
    body: JSON.stringify({ analyst, action }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    alert("Failed to classify: " + (err.description || res.status));
    return;
  }
  // Refresh queue + stats immediately.
  await refreshAll();
}

// ----- stats (KPI cards, global / unfiltered) ------------------------------ //
async function loadStats() {
  const res = await fetch("/api/stats");
  const stats = await res.json();

  setText("stat-total", stats.total);
  setText("stat-open", stats.open);

  // "Closed today" + "Avg MTTR today" derived from mttr_by_analyst rows.
  const today = new Date().toISOString().slice(0, 10);
  const todayRows = (stats.mttr_by_analyst || []).filter(r => r.date === today);
  const closedToday = todayRows.reduce((sum, r) => sum + r.count, 0);
  const totalSecs = todayRows.reduce((sum, r) => sum + r.avg_seconds * r.count, 0);
  const mttrMin = closedToday ? Math.round(totalSecs / closedToday / 60) : 0;

  setText("stat-closed-today", closedToday);
  setText("stat-mttr-today", mttrMin);
  setText("stat-sla-breach", stats.sla ? `${stats.sla.breach_rate}%` : "—");
  setText("stat-escalation", stats.escalation ? `${stats.escalation.rate}%` : "—");

  syncFilterOptions(stats);
  return stats;
}

// ----- distribution charts (respond to the active filters) ----------------- //
function tally(rows, key) {
  const counts = {};
  for (const r of rows) {
    const k = r[key] || "unknown";
    counts[k] = (counts[k] || 0) + 1;
  }
  return counts;
}

async function loadDistribution() {
  // Charts reflect the *filtered* alert population (all statuses).
  const res = await fetch("/api/alerts/all" + filterQuery());
  const alerts = await res.json();

  const byCategory = tally(alerts, "category");
  const bySeverity = tally(alerts, "severity");
  const bySource = tally(alerts, "source");

  if (categoryChart) {
    const labels = Object.keys(byCategory);
    categoryChart.data.labels = labels.map(l => l.replace("_", " "));
    categoryChart.data.datasets[0].data = labels.map(l => byCategory[l]);
    categoryChart.data.datasets[0].backgroundColor = labels.map(l => CATEGORY_COLORS[l] || "#64748b");
    categoryChart.update();
  }
  if (severityChart) {
    const order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
    const labels = order.filter(s => s in bySeverity);
    severityChart.data.labels = labels;
    severityChart.data.datasets[0].data = labels.map(l => bySeverity[l]);
    severityChart.data.datasets[0].backgroundColor = labels.map(l => SEVERITY_COLORS[l] || "#64748b");
    severityChart.update();
  }
  if (sourceChart) {
    const labels = Object.keys(bySource).sort();
    sourceChart.data.labels = labels;
    sourceChart.data.datasets[0].data = labels.map(l => bySource[l]);
    sourceChart.data.datasets[0].backgroundColor = labels.map((_, i) => SOURCE_PALETTE[i % SOURCE_PALETTE.length]);
    sourceChart.update();
  }
}

function initCharts() {
  const catCtx = document.getElementById("categoryChart");
  const sevCtx = document.getElementById("severityChart");
  const srcCtx = document.getElementById("sourceChart");
  if (catCtx) {
    categoryChart = new Chart(catCtx, {
      type: "doughnut",
      data: { labels: [], datasets: [{ data: [], backgroundColor: [] }] },
      options: { responsive: true, maintainAspectRatio: false,
                 plugins: { legend: { position: "right" } } },
    });
  }
  if (sevCtx) {
    severityChart = new Chart(sevCtx, {
      type: "bar",
      data: { labels: [], datasets: [{ label: "Alerts", data: [], backgroundColor: [] }] },
      options: { responsive: true, maintainAspectRatio: false,
                 scales: { y: { beginAtZero: true } },
                 plugins: { legend: { display: false } } },
    });
  }
  if (srcCtx) {
    sourceChart = new Chart(srcCtx, {
      type: "bar",
      data: { labels: [], datasets: [{ label: "Alerts", data: [], backgroundColor: [] }] },
      options: { indexAxis: "y", responsive: true, maintainAspectRatio: false,
                 scales: { x: { beginAtZero: true } },
                 plugins: { legend: { display: false } } },
    });
  }
}

// ----- utils --------------------------------------------------------------- //
function setText(id, value) {
  const el = document.getElementById(id);
  if (el) el.textContent = value;
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, c => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[c]));
}

async function refreshAll() {
  setStatus("refreshing…");
  try {
    await Promise.all([loadAlerts(), loadStats(), loadDistribution()]);
    setStatus("updated " + new Date().toLocaleTimeString());
  } catch (e) {
    setStatus("error");
    console.error(e);
  }
}

function initFilters() {
  ["filter-severity", "filter-source", "filter-assignee"].forEach(id => {
    document.getElementById(id)?.addEventListener("change", refreshAll);
  });
  document.getElementById("filter-clear")?.addEventListener("click", () => {
    ["filter-severity", "filter-source", "filter-assignee"].forEach(id => {
      const el = document.getElementById(id);
      if (el) el.value = "";
    });
    refreshAll();
  });
}

// ----- boot ---------------------------------------------------------------- //
document.addEventListener("DOMContentLoaded", () => {
  initAnalystInput();
  initFilters();
  initCharts();
  refreshAll();
  setInterval(refreshAll, REFRESH_MS);
});
