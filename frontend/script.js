const API_BASE = "/api/v1";

document.addEventListener("DOMContentLoaded", function () {
    checkBackend();
    loadRecentThreats();

    const refreshButton = document.getElementById("refresh-button");

    if (refreshButton) {
        refreshButton.addEventListener("click", function () {
            checkBackend();
            loadRecentThreats();
        });
    }
});

async function checkBackend() {
    const statusElement = document.getElementById("connection-status");

    if (!statusElement) {
        return;
    }

    try {
        const response = await fetch("/health");

        if (!response.ok) {
            throw new Error("Health check failed");
        }

        const result = await response.json();

        if (result.status === "healthy") {
            statusElement.textContent = "Backend Connected";
        } else {
            statusElement.textContent = "Backend Status Unknown";
        }
    } catch (error) {
        statusElement.textContent = "Backend Offline";
        console.error("Backend connection error:", error);
    }
}

async function loadRecentThreats() {
    const tableBody = document.getElementById("recent-threats");

    if (!tableBody) {
        return;
    }

    tableBody.innerHTML =
        '<tr><td colspan="4" class="empty-state">Loading recent threats...</td></tr>';

    try {
        const response = await fetch(API_BASE + "/threats");

        if (!response.ok) {
            throw new Error("Unable to load threat records");
        }

        const result = await response.json();

        let threats = [];

        if (Array.isArray(result)) {
            threats = result;
        } else if (Array.isArray(result.data)) {
            threats = result.data;
        } else if (Array.isArray(result.threats)) {
            threats = result.threats;
        } else if (Array.isArray(result.records)) {
            threats = result.records;
        }

        if (threats.length === 0) {
            tableBody.innerHTML =
                '<tr><td colspan="4" class="empty-state">No threat records found yet.</td></tr>';
            return;
        }

        tableBody.innerHTML = "";

        threats.slice(0, 10).forEach(function (threat) {
            const row = document.createElement("tr");

            const urlCell = document.createElement("td");
            urlCell.textContent =
                threat.url || threat.target_url || "Unknown URL";

            const scoreCell = document.createElement("td");
            scoreCell.textContent =
                threat.risk_score ?? threat.score ?? "N/A";

            const severityCell = document.createElement("td");
            const severity = String(
                threat.severity || threat.risk_level || "Unknown"
            ).toLowerCase();

            const badge = document.createElement("span");
            badge.className = "severity " + getSeverityClass(severity);
            badge.textContent =
                severity.charAt(0).toUpperCase() + severity.slice(1);

            severityCell.appendChild(badge);

            const dateCell = document.createElement("td");
            const dateValue =
                threat.created_at || threat.timestamp || threat.date;

            dateCell.textContent = dateValue
                ? formatDate(dateValue)
                : "—";

            row.append(urlCell, scoreCell, severityCell, dateCell);
            tableBody.appendChild(row);
        });
    } catch (error) {
        tableBody.innerHTML =
            '<tr><td colspan="4" class="empty-state">Unable to load threats. Check your backend.</td></tr>';

        console.error("Threat loading error:", error);
    }
}

function getSeverityClass(severity) {
    if (severity.includes("high") || severity.includes("critical")) {
        return "high";
    }

    if (severity.includes("medium") || severity.includes("moderate")) {
        return "medium";
    }

    return "low";
}

function formatDate(value) {
    const date = new Date(value);

    if (Number.isNaN(date.getTime())) {
        return String(value);
    }

    return date.toLocaleString();
}
