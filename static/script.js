let dataCache = [];

function updateUI(stats, logs) {
    document.getElementById("totalEvents").textContent = stats.total;
    document.getElementById("detectedAttacks").textContent = stats.detected;
    document.getElementById("criticalCount").textContent = stats.critical;
    document.getElementById("uniqueIP").textContent = stats.unique;

    renderTable(logs);
}

function renderTable(logs) {
    let body = document.getElementById("logBody");
    body.innerHTML = "";

    logs.forEach(e => {
        let row = `
        <tr>
            <td>${e.timestamp}</td>
            <td>${e.ip}</td>
            <td>${e.method}</td>
            <td>${e.url}</td>
            <td>${e.attack || ""}</td>
            <td>${e.status}</td>
        </tr>`;
        body.innerHTML += row;
    });
}

// Auto POST when file uploaded
function handleFileUpload() {
    let input = document.getElementById("upload");

    input.addEventListener("change", async () => {
        let formData = new FormData();
        formData.append("file", input.files[0]);

        let res = await fetch("/upload", {
            method: "POST",
            body: formData
        });

        let data = await res.json();
        dataCache = data.results;
        updateUI(data.stats, data.results);
    });
}

handleFileUpload();
