document.addEventListener("DOMContentLoaded", () => {
    checkHealth();
    initTrafficChart();
});

/**
 * Query the /health endpoint and update the header status badge.
 */
async function checkHealth() {
    const badge = document.getElementById("health-badge");
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
    } catch (error) {
        badge.textContent = "API Offline";
        badge.className = "badge badge-error";
        console.error("Health check failed:", error);
    }
}

/**
 * Initialize a placeholder Chart.js line chart for network traffic.
 */
function initTrafficChart() {
    const canvas = document.getElementById("trafficChart");
    if (!canvas || typeof Chart === "undefined") {
        return;
    }

    const labels = ["00:00", "00:05", "00:10", "00:15", "00:20", "00:25"];

    new Chart(canvas, {
        type: "line",
        data: {
            labels: labels,
            datasets: [
                {
                    label: "Packets / sec",
                    data: [0, 0, 0, 0, 0, 0],
                    borderColor: "#38bdf8",
                    backgroundColor: "rgba(56, 189, 248, 0.15)",
                    borderWidth: 2,
                    tension: 0.3,
                    fill: true,
                },
                {
                    label: "Anomalies",
                    data: [0, 0, 0, 0, 0, 0],
                    borderColor: "#ef4444",
                    backgroundColor: "rgba(239, 68, 68, 0.15)",
                    borderWidth: 2,
                    tension: 0.3,
                    fill: true,
                },
            ],
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    labels: {
                        color: "#f8fafc",
                    },
                },
            },
            scales: {
                x: {
                    ticks: { color: "#94a3b8" },
                    grid: { color: "rgba(51, 65, 85, 0.5)" },
                },
                y: {
                    beginAtZero: true,
                    suggestedMax: 10,
                    ticks: { color: "#94a3b8" },
                    grid: { color: "rgba(51, 65, 85, 0.5)" },
                },
            },
        },
    });
}
