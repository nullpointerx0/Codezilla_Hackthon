let logData = [];

document.getElementById("logInput").addEventListener("change", async function() {
    let file = this.files[0];
    let formData = new FormData();
    formData.append("file", file);

    let res = await fetch("/upload", {
        method: "POST",
        body: formData
    });

    let data = await res.json();

    // Update Stats
    document.getElementById("totalEvents").textContent = data.stats.total || 0;
    document.getElementById("detectedAttacks").textContent = data.stats.detected || 0;
    document.getElementById("criticalCount").textContent = data.stats.critical || 0;
    document.getElementById("uniqueIP").textContent = data.stats.unique || 0;

    // Store logs
    logData = data.results;
    renderTable(logData);
});

function renderTable(data) {
    let body = document.getElementById("logBody");
    body.innerHTML = "";

    data.forEach(row => {
        let html = `
        <tr>
            <td>${row.timestamp}</td>
            <td>${row.ip}</td>
            <td>${row.method}</td>
            <td>${row.url}</td>
            <td>${row.attack || ""}</td>
            <td>${row.status}</td>
        </tr>
        `;
        body.innerHTML += html;
    });
}

// SEARCH FILTER
document.getElementById("searchBox").addEventListener("input", function() {
    let q = this.value.toLowerCase();
    let filtered = logData.filter(e =>
        (e.ip && e.ip.toLowerCase().includes(q)) ||
        (e.url && e.url.toLowerCase().includes(q))
    );
    renderTable(filtered);
});
