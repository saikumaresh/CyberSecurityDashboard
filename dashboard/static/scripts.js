async function uploadFile() {
    const fileInput = document.getElementById('fileInput');
    const formData = new FormData();
    formData.append('file', fileInput.files[0]);

    const response = await fetch('/upload', {
        method: 'POST',
        body: formData,
    });
    const data = await response.json();

    if (data.error) {
        document.getElementById('output').innerText = "Error: " + data.error;
    } else {
        document.getElementById('output').innerText = "Anomalies Detected: " + data.anomalies_detected;
        document.getElementById('fullResult').innerText = data.result;
    }
}

// Call updateMetrics every 5 seconds
async function updateMetrics() {
    const response = await fetch('/api/metrics');
    const data = await response.json();

    document.getElementById('network-status').innerText = data.networkStatus;
    document.getElementById('mi-status').innerText = data.miStatus;
    document.getElementById('firebase-status').innerText = data.firebaseStatus;

    document.getElementById('sql-alert-time').innerText = data.sqlAlertTime;
    document.getElementById('ddos-alert-time').innerText = data.ddosAlertTime;
    document.getElementById('xss-alert-time').innerText = data.xssAlertTime;

    document.getElementById('total-alerts').innerText = data.totalAlerts;
    document.getElementById('critical-threats').innerText = data.criticalThreats;
    document.getElementById('response-time').innerText = data.avgResponseTime;
    document.getElementById('network-uptime').innerText = data.networkUptime;
}

setInterval(updateMetrics, 5000);  // Update every 5 seconds
