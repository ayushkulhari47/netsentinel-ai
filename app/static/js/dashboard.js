const POLL_INTERVAL_MS = 3000;

let severityChart = null;
let monitoringActive = true;
let pollTimerId = null;
let pollInFlight = false;
let currentAlerts = [];
let selectedAlertId = null;

document.addEventListener("DOMContentLoaded", () => {
    initSeverityChart();
    bindControls();
    bindModalEvents();
    checkHealth();
    runPollCycle();
});

function bindControls() {
    const toggleBtn = document.getElementById("monitoring-toggle-btn");
    if (toggleBtn) {
        toggleBtn.addEventListener("click", () => {
            if (monitoringActive) {
                stopMonitoring();
            } else {
                startMonitoring();
            }
        });
    }

    const filterIds = [
        "filter-severity",
        "filter-status",
        "filter-source-ip",
        "filter-destination-ip",
    ];
    for (const id of filterIds) {
        const el = document.getElementById(id);
        if (!el) {
            continue;
        }
        const eventName = el.tagName === "SELECT" ? "change" : "input";
        el.addEventListener(eventName, () => {
            loadDashboardData();
        });
    }

    const clearBtn = document.getElementById("clear-filters-btn");
    if (clearBtn) {
        clearBtn.addEventListener("click", () => {
            for (const id of filterIds) {
                const el = document.getElementById(id);
                if (el) {
                    el.value = "";
                }
            }
            loadDashboardData();
        });
    }
}

function bindModalEvents() {
    const modal = document.getElementById("alert-modal");
    const closeBtn = document.getElementById("modal-close-btn");
    const dismissBtn = document.getElementById("modal-dismiss-btn");
    const explainBtn = document.getElementById("generate-explanation-btn");

    if (closeBtn) {
        closeBtn.addEventListener("click", closeAlertModal);
    }
    if (dismissBtn) {
        dismissBtn.addEventListener("click", closeAlertModal);
    }
    if (modal) {
        modal.addEventListener("click", (event) => {
            if (event.target === modal) {
                closeAlertModal();
            }
        });
    }
    document.addEventListener("keydown", (event) => {
        if (event.key === "Escape") {
            closeAlertModal();
        }
    });
    if (explainBtn) {
        explainBtn.addEventListener("click", () => {
            if (selectedAlertId !== null) {
                generateAiExplanation(selectedAlertId);
            }
        });
    }
}

function startMonitoring() {
    monitoringActive = true;
    updateMonitoringUI();
    runPollCycle();
}

function stopMonitoring() {
    monitoringActive = false;
    if (pollTimerId !== null) {
        clearTimeout(pollTimerId);
        pollTimerId = null;
    }
    updateMonitoringUI();
}

function updateMonitoringUI() {
    const statusBadge = document.getElementById("monitoring-status");
    const toggleBtn = document.getElementById("monitoring-toggle-btn");

    if (statusBadge) {
        statusBadge.textContent = monitoringActive
            ? "Monitoring: Active (3s)"
            : "Monitoring: Paused";
        statusBadge.className = monitoringActive ? "badge badge-ok" : "badge badge-neutral";
    }
    if (toggleBtn) {
        toggleBtn.textContent = monitoringActive ? "Stop Monitoring" : "Start Monitoring";
    }
}

async function runPollCycle() {
    if (pollTimerId !== null) {
        clearTimeout(pollTimerId);
        pollTimerId = null;
    }
    await loadDashboardData();
    if (monitoringActive) {
        pollTimerId = setTimeout(runPollCycle, POLL_INTERVAL_MS);
    }
}

/**
 * Query /health and update the header status badge.
 */
async function checkHealth() {
    const badge = document.getElementById("health-badge");
    const captureBadge = document.getElementById("capture-badge");
    if (!badge) {
        return;
    }

    try {
        const response = await fetch("/health");
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }
        const data = await response.json();

        if (data.status === "ok") {
            badge.textContent = "API Online";
            badge.className = "badge badge-ok";
        } else {
            badge.textContent = "API Degraded";
            badge.className = "badge badge-error";
        }

        if (captureBadge && data.packet_capture === "not_configured") {
            captureBadge.textContent = "Capture: Standby";
        }
    } catch (error) {
        setApiOfflineState(`Health check failed (${error.message}).`);
    }
}

/**
 * Load summary KPIs and filtered alerts concurrently.
 */
async function loadDashboardData() {
    if (pollInFlight) {
        return;
    }
    pollInFlight = true;

    try {
        const [summaryOk, alertsOk] = await Promise.all([loadSummary(), loadAlerts()]);
        if (summaryOk && alertsOk) {
            setApiOnlineState();
            updateLastUpdated();
        }
    } finally {
        pollInFlight = false;
    }
}

async function loadSummary() {
    try {
        const response = await fetch("/api/summary");
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }
        const summary = await response.json();

        setText("total-alerts", summary.total_alerts ?? 0);
        setText("critical-alerts", summary.critical_alerts ?? 0);
        setText("high-alerts", summary.high_alerts ?? 0);
        setText("suspicious-ip-count", summary.suspicious_ip_count ?? 0);
        return true;
    } catch (error) {
        setApiOfflineState(`Unable to load summary (${error.message}).`);
        return false;
    }
}

function buildAlertsUrl() {
    const params = new URLSearchParams();
    const severity = getInputValue("filter-severity");
    const status = getInputValue("filter-status");
    const sourceIp = getInputValue("filter-source-ip");
    const destIp = getInputValue("filter-destination-ip");

    if (severity) {
        params.set("severity", severity);
    }
    if (status) {
        params.set("status", status);
    }
    if (sourceIp) {
        params.set("source_ip", sourceIp);
    }
    if (destIp) {
        params.set("destination_ip", destIp);
    }

    const queryString = params.toString();
    return queryString ? `/api/alerts?${queryString}` : "/api/alerts";
}

async function loadAlerts() {
    try {
        const response = await fetch(buildAlertsUrl());
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }
        const data = await response.json();
        const alerts = Array.isArray(data.alerts) ? data.alerts : [];
        currentAlerts = alerts;

        renderAlertsTable(alerts);
        updateSeverityChart(alerts);
        return true;
    } catch (error) {
        setApiOfflineState(`Unable to load alerts (${error.message}).`);
        return false;
    }
}

function setApiOnlineState() {
    const badge = document.getElementById("health-badge");
    const errorBanner = document.getElementById("api-error-banner");

    if (badge) {
        badge.textContent = "API Online";
        badge.className = "badge badge-ok";
    }
    if (errorBanner) {
        errorBanner.textContent = "";
        errorBanner.classList.add("hidden");
    }
}

function setApiOfflineState(message) {
    const badge = document.getElementById("health-badge");
    const errorBanner = document.getElementById("api-error-banner");

    if (badge) {
        badge.textContent = "API Offline";
        badge.className = "badge badge-error";
    }
    if (errorBanner) {
        errorBanner.textContent = `API error: ${message}`;
        errorBanner.classList.remove("hidden");
    }
}

function updateLastUpdated() {
    const el = document.getElementById("last-updated");
    if (el) {
        el.textContent = `Last updated: ${new Date().toLocaleTimeString()}`;
    }
}

/**
 * Render alerts safely using DOM APIs only.
 */
function renderAlertsTable(alerts) {
    const emptyState = document.getElementById("alerts-empty-state");
    const tableWrapper = document.getElementById("alerts-table-wrapper");
    const tableBody = document.getElementById("alerts-table-body");
    const countPill = document.getElementById("alerts-count-pill");

    if (!emptyState || !tableWrapper || !tableBody) {
        return;
    }

    tableBody.replaceChildren();

    if (countPill) {
        const label = alerts.length === 1 ? "1 Alert" : `${alerts.length} Alerts`;
        countPill.textContent = label;
    }

    if (alerts.length === 0) {
        emptyState.classList.remove("hidden");
        tableWrapper.classList.add("hidden");
        return;
    }

    emptyState.classList.add("hidden");
    tableWrapper.classList.remove("hidden");

    for (const alert of alerts) {
        const row = document.createElement("tr");
        row.addEventListener("click", () => openAlertModal(alert));

        row.appendChild(createCell(formatTimestamp(alert.timestamp), "mono"));
        row.appendChild(createCell(formatEndpoint(alert.source_ip, alert.source_port), "mono"));
        row.appendChild(
            createCell(formatEndpoint(alert.destination_ip, alert.destination_port), "mono")
        );
        row.appendChild(createCell(alert.attack_type || "-"));
        row.appendChild(createSeverityCell(alert.severity));
        row.appendChild(createCell(formatScore(alert.threat_score)));
        row.appendChild(createCell(alert.status || "open"));

        const actionCell = document.createElement("td");
        const detailsBtn = document.createElement("button");
        detailsBtn.type = "button";
        detailsBtn.className = "btn btn-outline btn-small";
        detailsBtn.textContent = "Inspect";
        detailsBtn.addEventListener("click", (event) => {
            event.stopPropagation();
            openAlertModal(alert);
        });
        actionCell.appendChild(detailsBtn);
        row.appendChild(actionCell);

        tableBody.appendChild(row);
    }
}

function openAlertModal(alert) {
    const modal = document.getElementById("alert-modal");
    if (!modal || !alert) {
        return;
    }

    selectedAlertId = alert.id;

    setText("modal-title", alert.attack_type || "Alert Details");
    setText(
        "modal-subtitle",
        `${formatEndpoint(alert.source_ip, alert.source_port)} -> ${formatEndpoint(
            alert.destination_ip,
            alert.destination_port
        )} (${alert.protocol || "-"}) • ${formatTimestamp(alert.timestamp)}`
    );

    const sevContainer = document.getElementById("modal-severity");
    if (sevContainer) {
        sevContainer.replaceChildren(createSeverityBadge(alert.severity));
    }

    setText("modal-threat-score", formatScore(alert.threat_score));
    setText(
        "modal-anomaly-score",
        typeof alert.anomaly_score === "number" ? alert.anomaly_score.toFixed(4) : "0.0000"
    );
    setText("modal-status", alert.status || "open");
    setText("modal-explanation", alert.explanation || "No explanation recorded.");

    resetAiSection();
    modal.classList.remove("hidden");

    if (alert.source_ip) {
        loadThreatIntelForModal(alert.source_ip, alert.id);
    }
}

function closeAlertModal() {
    const modal = document.getElementById("alert-modal");
    if (modal) {
        modal.classList.add("hidden");
    }
    selectedAlertId = null;
}

function resetAiSection() {
    const placeholder = document.getElementById("modal-ai-placeholder");
    const structured = document.getElementById("modal-ai-structured");
    const sourcePill = document.getElementById("modal-ai-source");
    const explainBtn = document.getElementById("generate-explanation-btn");

    if (placeholder) {
        placeholder.textContent =
            'Click "Generate AI Explanation" to request an on-demand structured analysis.';
        placeholder.classList.remove("hidden");
    }
    if (structured) {
        structured.classList.add("hidden");
    }
    if (sourcePill) {
        sourcePill.textContent = "";
        sourcePill.classList.add("hidden");
    }
    if (explainBtn) {
        explainBtn.disabled = false;
        explainBtn.textContent = "Generate AI Explanation";
    }
}

async function loadThreatIntelForModal(sourceIp, expectedAlertId) {
    const container = document.getElementById("modal-threat-intel");
    if (!container) {
        return;
    }

    const loadingText = document.createElement("p");
    loadingText.className = "muted";
    loadingText.textContent = `Checking threat intelligence for ${sourceIp}...`;
    container.replaceChildren(loadingText);

    try {
        const response = await fetch(`/api/threat-intel/${encodeURIComponent(sourceIp)}`);
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }
        const intel = await response.json();
        if (selectedAlertId !== expectedAlertId) {
            return;
        }

        const items = [
            `Reputation: ${intel.reputation || "unknown"}`,
            `Provider: ${intel.provider || "none"}`,
            `Abuse Score: ${intel.abuse_score ?? 0}/100`,
            `Confidence: ${formatConfidence(intel.confidence)}`,
        ];
        if (Array.isArray(intel.categories) && intel.categories.length > 0) {
            items.push(`Categories: ${intel.categories.join(", ")}`);
        }

        const list = document.createElement("ul");
        list.className = "detail-list";
        for (const text of items) {
            const li = document.createElement("li");
            li.textContent = text;
            list.appendChild(li);
        }

        const nodes = [list];
        if (intel.summary) {
            const summaryP = document.createElement("p");
            summaryP.className = "muted";
            summaryP.textContent = intel.summary;
            nodes.push(summaryP);
        }
        container.replaceChildren(...nodes);
    } catch (error) {
        if (selectedAlertId !== expectedAlertId) {
            return;
        }
        const errP = document.createElement("p");
        errP.className = "muted";
        errP.textContent = `Threat intelligence unavailable (${error.message}).`;
        container.replaceChildren(errP);
    }
}

async function generateAiExplanation(alertId) {
    const explainBtn = document.getElementById("generate-explanation-btn");
    const placeholder = document.getElementById("modal-ai-placeholder");
    const structured = document.getElementById("modal-ai-structured");
    const sourcePill = document.getElementById("modal-ai-source");

    if (explainBtn) {
        explainBtn.disabled = true;
        explainBtn.textContent = "Generating...";
    }

    try {
        const response = await fetch(`/api/alerts/${encodeURIComponent(alertId)}/explain`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({}),
        });
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }
        const data = await response.json();
        const exp = data.explanation;

        if (!exp || selectedAlertId !== alertId) {
            return;
        }

        setText("modal-ai-summary", exp.summary || "");
        setText("modal-ai-why", exp.why_it_matters || "");
        setText("modal-confidence-note", exp.confidence_note || "");
        renderTextList("modal-evidence-list", exp.evidence);
        renderTextList("modal-actions-list", exp.recommended_actions);

        if (sourcePill) {
            sourcePill.textContent =
                exp.source === "openai"
                    ? `OpenAI (${exp.model || "configured"})`
                    : "Rule-based Fallback";
            sourcePill.classList.remove("hidden");
        }
        if (placeholder) {
            placeholder.classList.add("hidden");
        }
        if (structured) {
            structured.classList.remove("hidden");
        }

        // Sync explanation text in the modal & cached alert without changing scores.
        if (data.alert && data.alert.explanation) {
            setText("modal-explanation", data.alert.explanation);
            const idx = currentAlerts.findIndex((a) => a.id === alertId);
            if (idx !== -1) {
                currentAlerts[idx] = data.alert;
            }
        }
    } catch (error) {
        if (placeholder) {
            placeholder.textContent = `Unable to generate explanation (${error.message}).`;
            placeholder.classList.remove("hidden");
        }
        if (structured) {
            structured.classList.add("hidden");
        }
    } finally {
        if (explainBtn) {
            explainBtn.disabled = false;
            explainBtn.textContent = "Generate AI Explanation";
        }
    }
}

function renderTextList(elementId, items) {
    const listEl = document.getElementById(elementId);
    if (!listEl) {
        return;
    }
    const entries = Array.isArray(items) ? items : [];
    const nodes = entries.map((item) => {
        const li = document.createElement("li");
        li.textContent = String(item);
        return li;
    });
    listEl.replaceChildren(...nodes);
}

/**
 * Initialize an empty Chart.js bar chart for alert severity breakdown.
 */
function initSeverityChart() {
    const canvas = document.getElementById("trafficChart");
    if (!canvas || typeof Chart === "undefined") {
        return;
    }

    severityChart = new Chart(canvas, {
        type: "bar",
        data: {
            labels: ["Critical", "High", "Medium", "Low"],
            datasets: [
                {
                    label: "Alerts",
                    data: [0, 0, 0, 0],
                    backgroundColor: [
                        "rgba(239, 68, 68, 0.75)",
                        "rgba(249, 115, 22, 0.75)",
                        "rgba(245, 158, 11, 0.75)",
                        "rgba(34, 197, 94, 0.75)",
                    ],
                    borderColor: ["#ef4444", "#f97316", "#f59e0b", "#22c55e"],
                    borderWidth: 1,
                    borderRadius: 6,
                },
            ],
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { display: false },
            },
            scales: {
                x: {
                    ticks: { color: "#94a3b8" },
                    grid: { color: "rgba(51, 65, 85, 0.4)" },
                },
                y: {
                    beginAtZero: true,
                    ticks: {
                        color: "#94a3b8",
                        precision: 0,
                    },
                    grid: { color: "rgba(51, 65, 85, 0.4)" },
                },
            },
        },
    });
}

function updateSeverityChart(alerts) {
    const statusPill = document.getElementById("chart-status-pill");
    if (statusPill) {
        statusPill.textContent = alerts.length === 0 ? "No Alerts" : "Live Database";
    }

    if (!severityChart) {
        return;
    }

    const counts = { critical: 0, high: 0, medium: 0, low: 0 };
    for (const alert of alerts) {
        const sev = String(alert.severity || "").toLowerCase();
        if (sev in counts) {
            counts[sev] += 1;
        }
    }

    severityChart.data.datasets[0].data = [
        counts.critical,
        counts.high,
        counts.medium,
        counts.low,
    ];
    severityChart.update();
}

function getInputValue(id) {
    const el = document.getElementById(id);
    return el ? el.value.trim() : "";
}

function setText(id, value) {
    const el = document.getElementById(id);
    if (el) {
        el.textContent = String(value);
    }
}

function createCell(text, className = "") {
    const td = document.createElement("td");
    td.textContent = text;
    if (className) {
        td.className = className;
    }
    return td;
}

function createSeverityBadge(severity) {
    const badge = document.createElement("span");
    const normalized = String(severity || "low").toLowerCase();
    const valid = ["critical", "high", "medium", "low"].includes(normalized)
        ? normalized
        : "low";
    badge.className = `severity-badge severity-${valid}`;
    badge.textContent = valid;
    return badge;
}

function createSeverityCell(severity) {
    const td = document.createElement("td");
    td.appendChild(createSeverityBadge(severity));
    return td;
}

function formatEndpoint(ip, port) {
    if (!ip) {
        return "-";
    }
    return port !== null && port !== undefined ? `${ip}:${port}` : ip;
}

function formatTimestamp(isoString) {
    if (!isoString) {
        return "-";
    }
    const date = new Date(isoString);
    if (Number.isNaN(date.getTime())) {
        return isoString;
    }
    return date.toLocaleString();
}

function formatScore(score) {
    if (typeof score !== "number") {
        return "-";
    }
    return score.toFixed(1);
}

function formatConfidence(confidence) {
    if (typeof confidence !== "number") {
        return "-";
    }
    return `${Math.round(confidence * 100)}%`;
}
