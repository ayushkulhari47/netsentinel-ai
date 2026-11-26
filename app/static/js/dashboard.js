let severityChart = null;

document.addEventListener("DOMContentLoaded", () => {
    checkHealth();
    initSeverityChart();
    loadDashboardData();
});

/**
 * Query the /health endpoint and update the header status badge.
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
        badge.textContent = "API Offline";
        badge.className = "badge badge-error";
        console.error("Health check failed:", error);
    }
}

/**
 * Load alert summary KPIs and recent alerts from the backend API.
 */
async function loadDashboardData() {
    await Promise.all([loadSummary(), loadAlerts()]);
}

/**
 * Fetch summary counts from GET /api/summary and update KPI cards.
 */
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
    } catch (error) {
        console.error("Failed to load summary:", error);
    }
}

/**
 * Fetch alerts from GET /api/alerts and update the table and chart.
 */
async function loadAlerts() {
    try {
        const response = await fetch("/api/alerts");
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }
        const data = await response.json();
        const alerts = Array.isArray(data.alerts) ? data.alerts : [];

        renderAlertsTable(alerts);
        updateSeverityChart(alerts);
    } catch (error) {
        console.error("Failed to load alerts:", error);
    }
}

/**
 * Render alerts in the dashboard table, or show the empty state when none exist.
 */
function renderAlertsTable(alerts) {
    const emptyState = document.getElementById("alerts-empty-state");
    const tableWrapper = document.getElementById("alerts-table-wrapper");
    const tableBody = document.getElementById("alerts-table-body");
    const countPill = document.getElementById("alerts-count-pill");

    if (!emptyState || !tableWrapper || !tableBody) {
        return;
    }

    tableBody.innerHTML = "";

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
        if (alert.explanation) {
            row.title = alert.explanation;
        }

        row.appendChild(createCell(formatTimestamp(alert.timestamp), "mono"));
        row.appendChild(createCell(formatEndpoint(alert.source_ip, alert.source_port), "mono"));
        row.appendChild(
            createCell(formatEndpoint(alert.destination_ip, alert.destination_port), "mono")
        );
        row.appendChild(createCell(alert.protocol || "-", "mono"));
        row.appendChild(createCell(alert.attack_type || "-"));
        row.appendChild(createSeverityCell(alert.severity));
        row.appendChild(createCell(formatScore(alert.threat_score)));
        row.appendChild(createCell(formatConfidence(alert.confidence)));
        row.appendChild(createCell(alert.status || "open"));

        tableBody.appendChild(row);
    }
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

/**
 * Update the severity chart using live alerts returned by /api/alerts.
 */
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

function createSeverityCell(severity) {
    const td = document.createElement("td");
    const badge = document.createElement("span");
    const normalized = String(severity || "low").toLowerCase();
    const valid = ["critical", "high", "medium", "low"].includes(normalized)
        ? normalized
        : "low";
    badge.className = `severity-badge severity-${valid}`;
    badge.textContent = valid;
    td.appendChild(badge);
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
