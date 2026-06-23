// SOC Dashboard — alert queue + live stats.
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

let categoryChart, severityChart;

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
  const res = await fetch("/api/alerts");
  const alerts = await res.json();
  const tbody = document.getElementById("alert-rows");
  if (!tbody) return;

  if (!alerts.length) {
    tbody.innerHTML =
      `<tr><td colspan="6" class="text-center text-secondary">Queue is clear 🎉</td></tr>`;
    return;
  }

  tbody.innerHTML = alerts.map(a => `
    <tr data-id="${a.id}">
      <td><span class="badge sev-badge ${SEVERITY_BADGE[a.severity] || "text-bg-secondary"}">${a.severity}</span></td>
      <td>${escapeHtml(a.title)}</td>
      <td><span class="text-capitalize">${a.category.replace("_", " ")}</span></td>
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
  const res = await fetch(`/api/alerts/${id}/classify`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
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

// ----- stats --------------------------------------------------------------- //
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

  updateCharts(stats);
  return stats;
}

function initCharts() {
  const catCtx = document.getElementById("categoryChart");
  const sevCtx = document.getElementById("severityChart");
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
}

function updateCharts(stats) {
  if (categoryChart && stats.by_category) {
    const labels = Object.keys(stats.by_category);
    categoryChart.data.labels = labels.map(l => l.replace("_", " "));
    categoryChart.data.datasets[0].data = labels.map(l => stats.by_category[l]);
    categoryChart.data.datasets[0].backgroundColor =
      labels.map(l => CATEGORY_COLORS[l] || "#64748b");
    categoryChart.update();
  }
  if (severityChart && stats.by_severity) {
    const order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
    const labels = order.filter(s => s in stats.by_severity);
    severityChart.data.labels = labels;
    severityChart.data.datasets[0].data = labels.map(l => stats.by_severity[l]);
    severityChart.data.datasets[0].backgroundColor =
      labels.map(l => SEVERITY_COLORS[l] || "#64748b");
    severityChart.update();
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
    await Promise.all([loadAlerts(), loadStats()]);
    setStatus("updated " + new Date().toLocaleTimeString());
  } catch (e) {
    setStatus("error");
    console.error(e);
  }
}

// ----- boot ---------------------------------------------------------------- //
document.addEventListener("DOMContentLoaded", () => {
  initAnalystInput();
  initCharts();
  refreshAll();
  setInterval(refreshAll, REFRESH_MS);
});
