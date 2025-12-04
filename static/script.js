let tableData = [];

async function uploadFile() {
  let file = document.getElementById("fileInput").files[0];
  if (!file) return alert("Select a file first!");

  let form = new FormData();
  form.append("file", file);

  await fetch("/api/upload", {
    method: "POST",
    body: form
  });

  loadResults();
}

// Load results from API
async function loadResults() {
  const res = await fetch("/api/results");
  tableData = await res.json();

  renderTable(tableData);
  updateStats(tableData);
  renderChart(tableData);
}

function renderTable(data) {
  let body = document.getElementById("tableBody");
  body.innerHTML = "";

  data.forEach(row => {
    body.innerHTML += `
    <tr>
      <td>${row.timestamp || '-'}</td>
      <td>${row.ip}</td>
      <td>${row.method}</td>
      <td>${row.url}</td>
      <td>${row.attack_type}</td>
      <td>${row.classification}</td>
    </tr>`;
  });
}

function updateStats(data) {
  document.getElementById("totalEvents").innerText = data.length;
  document.getElementById("uniqueIP").innerText =
    new Set(data.map(item => item.ip)).size;

  let attacks = data.filter(d => d.attack_type !== "Normal").length;
  document.getElementById("totalAttacks").innerText = attacks;

  let critical = data.filter(d => d.classification === "Successful").length;
  document.getElementById("criticalCount").innerText = critical;
}

function renderChart(data) {
  let counts = {
    SQLi: 0,
    XSS: 0,
    CMD: 0,
    LFI: 0
  };

  data.forEach(d => {
    if (counts[d.attack_type] !== undefined) {
      counts[d.attack_type]++;
    }
  });

  new Chart(document.getElementById("attackChart"), {
    type: "doughnut",
    data: {
      labels: ["SQLi", "XSS", "CMD", "LFI"],
      datasets: [{
        data: [
          counts.SQLi,
          counts.XSS,
          counts.CMD,
          counts.LFI
        ],
        backgroundColor: [
          "#8b5cf6", "#facc15", "#ef4444", "#3b82f6"
        ]
      }]
    }
  });
}

// Search filter
function filterData() {
  let q = document.getElementById("filterInput").value.toLowerCase();

  let filtered = tableData.filter(r =>
    r.ip.toLowerCase().includes(q) ||
    r.url.toLowerCase().includes(q)
  );

  renderTable(filtered);
}
