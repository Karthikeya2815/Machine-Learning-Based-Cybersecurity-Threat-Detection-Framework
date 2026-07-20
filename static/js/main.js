// Global state
let networkChartInstance = null;
const gaugeCircumference = 2 * Math.PI * 70; // 439.82

// Shortcut Templates for Phishing Tab
const emailTemplates = {
    phishing1: "URGENT: Your Bank of America account has been suspended! We detected unusual security activity. Click here to verify your banking details immediately: http://bank-verify-portal.net/login",
    phishing2: "Congratulations customer! You've won a free Apple iPhone 14 Pro Max! Your email was selected as the monthly winner. Click to claim your prize now: http://claim-prize-winners.info/verify",
    legit: "Hi Team, Just wanted to follow up on our conversation yesterday. Please review the attached spreadsheet before our meeting tomorrow. Thanks, John"
};

// Initialize elements
document.addEventListener("DOMContentLoaded", () => {
    // Start Live Clock
    setInterval(updateClock, 1000);
    updateClock();

    // Fetch initial model metadata
    fetchModelMetrics();

    // Setup initial network chart
    initNetworkChart();

    // Populate initial network simulated logs
    simulateNewNetworkPackets();

    // Setup gauges initial state
    setGaugeValue("malware-gauge", 0);
    setGaugeValue("phishing-gauge", 0);
});

// Update Header Live Clock
function updateClock() {
    const clockEl = document.getElementById("live-clock");
    const now = new Date();
    clockEl.textContent = now.toLocaleTimeString();
}

// Navigation Tabs switching
function switchTab(tabId) {
    // Deactivate all nav buttons & panes
    document.querySelectorAll(".nav-item").forEach(el => el.classList.remove("active"));
    document.querySelectorAll(".tab-pane").forEach(el => el.classList.remove("active"));

    // Find target items
    const activeBtn = Array.from(document.querySelectorAll(".nav-item")).find(el => el.textContent.toLowerCase().includes(tabId));
    if (activeBtn) activeBtn.classList.add("active");
    
    const activePane = document.getElementById(`tab-${tabId}`);
    if (activePane) activePane.classList.add("active");

    // Update Titles
    const titleEl = document.getElementById("page-title");
    const subtitleEl = document.getElementById("page-subtitle");
    
    switch (tabId) {
        case "dashboard":
            titleEl.textContent = "Threat Detection Center";
            subtitleEl.textContent = "Overview of network and system threat profiles";
            break;
        case "network":
            titleEl.textContent = "Network Intrusion Feed";
            subtitleEl.textContent = "Real-time inspection of active network flows and packet headers";
            break;
        case "malware":
            titleEl.textContent = "Malware PE Feature Classifier";
            subtitleEl.textContent = "Heuristic-based Random Forest analysis of simulated executable features";
            break;
        case "phishing":
            titleEl.textContent = "Phishing NLP Scanner";
            subtitleEl.textContent = "Lexical and semantic checking of email bodies using TF-IDF vectors";
            break;
        case "metrics":
            titleEl.textContent = "Model Engineering Metrics";
            subtitleEl.textContent = "Performance breakdown of underlying trained scikit-learn models";
            break;
    }
}

// Load Model Specs
async function fetchModelMetrics() {
    try {
        const response = await fetch("/api/metrics");
        const data = await response.json();
        
        // Update Autoencoder threshold view
        const thresh = data.network.threshold;
        document.getElementById("info-ae-thresh").textContent = thresh.toFixed(6);
        document.getElementById("info-ae-shape").textContent = `${data.network.features_count} inputs`;
        document.getElementById("info-mw-trees").textContent = `${data.malware.estimators} Trees`;
        document.getElementById("info-ph-vocab").textContent = `${data.phishing.vocabulary_size} Features`;
    } catch (err) {
        console.error("Error loading model metrics:", err);
    }
}

// Initialize Anomaly Line Chart
function initNetworkChart() {
    const ctx = document.getElementById("networkDashboardChart").getContext("2d");
    
    // Gradient configuration
    const gradient = ctx.createLinearGradient(0, 0, 0, 300);
    gradient.addColorStop(0, "rgba(0, 240, 255, 0.2)");
    gradient.addColorStop(1, "rgba(0, 240, 255, 0)");

    networkChartInstance = new Chart(ctx, {
        type: 'line',
        data: {
            labels: Array(15).fill(""),
            datasets: [{
                label: 'Anomaly Score',
                data: Array(15).fill(0),
                borderColor: '#00f0ff',
                borderWidth: 2,
                backgroundColor: gradient,
                fill: true,
                tension: 0.4,
                pointBackgroundColor: '#00f0ff',
                pointRadius: 3
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { display: false }
            },
            scales: {
                y: {
                    grid: { color: 'rgba(255, 255, 255, 0.05)' },
                    ticks: { color: '#94a3b8' },
                    min: 0,
                    max: 0.1
                },
                x: {
                    grid: { display: false },
                    ticks: { display: false }
                }
            }
        }
    });
}

// Fetch Simulated Network Data and Render
async function simulateNewNetworkPackets() {
    try {
        const response = await fetch("/api/simulate/network");
        const packets = await response.json();

        // Update Chart
        const scores = packets.map(p => p.anomaly_score);
        const labels = packets.map((_, i) => `#${i + 1}`);
        
        if (networkChartInstance) {
            networkChartInstance.data.labels = labels;
            networkChartInstance.data.datasets[0].data = scores;
            // Adjust y-axis range based on max score
            const maxScore = Math.max(...scores);
            networkChartInstance.options.scales.y.max = maxScore * 1.3;
            networkChartInstance.update();
        }

        // Update Log Table
        const tbody = document.querySelector("#network-table tbody");
        tbody.innerHTML = "";
        
        packets.forEach((p, idx) => {
            const tr = document.createElement("tr");
            const isAnomaly = p.is_anomaly;
            const rowClass = isAnomaly ? "text-danger" : "";
            
            tr.innerHTML = `
                <td class="${rowClass}"><strong>${p.protocol_type.toUpperCase()}</strong></td>
                <td>${p.service}</td>
                <td><code style="font-family: JetBrains Mono">${p.flag}</code></td>
                <td>${Math.round(p.bytes_sent)}</td>
                <td>${Math.round(p.bytes_received)}</td>
                <td>${p.duration.toFixed(2)}</td>
                <td>${p.anomaly_score.toFixed(6)}</td>
                <td>
                    <span class="badge ${isAnomaly ? 'badge-danger' : 'badge-success'}">
                        ${isAnomaly ? 'Anomaly' : 'Safe'}
                    </span>
                </td>
            `;
            tbody.appendChild(tr);
        });

    } catch (err) {
        console.error("Error simulating network packets:", err);
    }
}

// Gauge Utility
function setGaugeValue(gaugeId, percent) {
    const circle = document.getElementById(gaugeId);
    if (!circle) return;
    const offset = gaugeCircumference - (percent * gaugeCircumference);
    circle.style.strokeDasharray = `${gaugeCircumference} ${gaugeCircumference}`;
    circle.style.strokeDashoffset = offset;
}

// Submit Malware PE classifier
async function analyzeMalware(event) {
    event.preventDefault();
    
    // Read features
    const features = {
        filesize: parseInt(document.getElementById("filesize").value),
        num_sections: parseInt(document.getElementById("num_sections").value),
        num_imports: parseInt(document.getElementById("num_imports").value),
        num_exports: parseInt(document.getElementById("num_exports").value),
        contains_packer_sig: document.getElementById("contains_packer_sig").checked ? 1 : 0,
        entry_point_entropy: parseFloat(document.getElementById("entry_point_entropy").value),
        avg_section_entropy: parseFloat(document.getElementById("avg_section_entropy").value),
        has_digital_signature: document.getElementById("has_digital_signature").checked ? 1 : 0,
        has_tls_callback: document.getElementById("has_tls_callback").checked ? 1 : 0,
        has_anti_debug: document.getElementById("has_anti_debug").checked ? 1 : 0,
        has_anti_vm: 0 // Default setting
    };

    // Show loading indicator / transition UI
    const placeholder = document.getElementById("malware-result-placeholder");
    const resultBox = document.getElementById("malware-result-box");
    placeholder.classList.add("hidden");
    resultBox.classList.remove("hidden");

    try {
        const response = await fetch("/api/detect/malware", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ features })
        });
        const data = await response.json();

        // Update score display
        const prob = data.malware_probability;
        const probPercent = Math.round(prob * 100);
        document.getElementById("malware-prob").textContent = `${probPercent}%`;
        document.getElementById("malware-meta-conf").textContent = `${(prob * 100).toFixed(2)}%`;
        
        // Color adjustments
        const gauge = document.getElementById("malware-gauge");
        const banner = document.getElementById("malware-banner");
        const statusTxt = document.getElementById("malware-status-txt");
        
        setGaugeValue("malware-gauge", prob);

        if (data.is_malware) {
            gauge.style.stroke = "#ff1744"; // Red
            banner.className = "status-banner danger";
            statusTxt.textContent = "MALICIOUS EXECUTABLE";
        } else {
            gauge.style.stroke = "#00e676"; // Green
            banner.className = "status-banner safe";
            statusTxt.textContent = "BENIGN / SAFE";
        }

    } catch (err) {
        console.error("Error analyzing malware:", err);
    }
}

// Shortcut template filler for Phishing Tab
function fillEmailTemplate(type) {
    const text = emailTemplates[type] || "";
    document.getElementById("email_content").value = text;
}

// Submit Phishing scanner
async function analyzePhishing(event) {
    event.preventDefault();

    const email = document.getElementById("email_content").value;

    const placeholder = document.getElementById("phishing-result-placeholder");
    const resultBox = document.getElementById("phishing-result-box");
    placeholder.classList.add("hidden");
    resultBox.classList.remove("hidden");

    try {
        const response = await fetch("/api/detect/phishing", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ email })
        });
        const data = await response.json();

        // Update score
        const prob = data.phishing_probability;
        const probPercent = Math.round(prob * 100);
        document.getElementById("phishing-prob").textContent = `${probPercent}%`;

        const gauge = document.getElementById("phishing-gauge");
        const banner = document.getElementById("phishing-banner");
        const statusTxt = document.getElementById("phishing-status-txt");
        
        setGaugeValue("phishing-gauge", prob);

        if (data.is_phishing) {
            gauge.style.stroke = "#ff1744";
            banner.className = "status-banner danger";
            statusTxt.textContent = "PHISHING DETECTED";
        } else {
            gauge.style.stroke = "#00e676";
            banner.className = "status-banner safe";
            statusTxt.textContent = "LEGITIMATE EMAIL";
        }

        // Highlight NLP checks
        const features = data.features;
        updateIndicator("ind-urgent", features.has_urgent_subject);
        updateIndicator("ind-links", features.has_suspicious_links || features.link_count > 0);
        updateIndicator("ind-password", features.has_password_request);
        updateIndicator("ind-money", features.has_financial_terms);
        updateIndicator("ind-spell", features.has_misspellings);

    } catch (err) {
        console.error("Error analyzing phishing:", err);
    }
}

// Indicator checkbox checker helper
function updateIndicator(elId, isTrue) {
    const el = document.getElementById(elId);
    if (!el) return;
    const icon = el.querySelector("i");
    
    if (isTrue) {
        icon.className = "fa-solid fa-circle-check status-on";
    } else {
        icon.className = "fa-solid fa-circle-xmark status-off";
    }
}

// Trigger mock AI retraining
function retrainModels() {
    const btn = document.getElementById("retrain-btn");
    const originalText = btn.innerHTML;
    
    btn.disabled = true;
    btn.innerHTML = `<i class="fa-solid fa-circle-notch fa-spin"></i> Optimizing models...`;
    
    setTimeout(() => {
        btn.disabled = false;
        btn.innerHTML = originalText;
        alert("Models successfully retrained and optimized! Accuracy scores recalculated.");
    }, 2000);
}
