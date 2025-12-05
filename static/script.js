// Combined JavaScript for single-page application

let allResults = [];
let filteredResults = [];

// DOM elements
const formFileInput = document.getElementById('formFileInput');
const uploadBox = document.getElementById('uploadBox');
const uploadContent = document.getElementById('uploadContent');
const submitBtn = document.getElementById('submitBtn');
const uploadForm = document.getElementById('uploadForm');
const loading = document.getElementById('loading');
const errorSection = document.getElementById('errorSection');
const statsSection = document.getElementById('statsSection');
const resultsSection = document.getElementById('resultsSection');
const searchInput = document.getElementById('searchInput');
const filterClassification = document.getElementById('filterClassification');
const filterSeverity = document.getElementById('filterSeverity');
const resultsBody = document.getElementById('resultsBody');
const noResults = document.getElementById('noResults');
const exportBtn = document.getElementById('exportBtn');

// File upload handling
uploadBox.addEventListener('click', () => formFileInput.click());

formFileInput.addEventListener('change', function(e) {
    handleFileSelect(e);
});

uploadBox.addEventListener('dragover', (e) => {
    e.preventDefault();
    e.stopPropagation();
    uploadBox.classList.add('dragover');
});

uploadBox.addEventListener('dragleave', (e) => {
    e.preventDefault();
    e.stopPropagation();
    uploadBox.classList.remove('dragover');
});

uploadBox.addEventListener('drop', (e) => {
    e.preventDefault();
    e.stopPropagation();
    uploadBox.classList.remove('dragover');
    
    const files = e.dataTransfer.files;
    if (files.length > 0) {
        const file = files[0];
        if (!file.name.endsWith('.csv')) {
            showError('Please select a CSV file.');
            return;
        }
        
        const dataTransfer = new DataTransfer();
        dataTransfer.items.add(file);
        formFileInput.files = dataTransfer.files;
        
        handleFileSelect({ target: formFileInput });
    }
});

function handleFileSelect(e) {
    const file = e.target.files[0];
    if (!file) return;
    
    if (!file.name.endsWith('.csv')) {
        showError('Please select a CSV file.');
        formFileInput.value = '';
        submitBtn.disabled = true;
        return;
    }
    
    submitBtn.disabled = false;
    errorSection.style.display = 'none';
    
    uploadContent.innerHTML = `
        <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path>
            <polyline points="14 2 14 8 20 8"></polyline>
            <line x1="16" y1="13" x2="8" y2="13"></line>
            <line x1="16" y1="17" x2="8" y2="17"></line>
            <polyline points="10 9 9 9 8 9"></polyline>
        </svg>
        <h3>${file.name}</h3>
        <p>Ready to analyze</p>
        <p class="file-info">Click "Analyze Logs" to proceed</p>
    `;
}

// Form submission - use AJAX to stay on same page
uploadForm.addEventListener('submit', async function(e) {
    e.preventDefault();
    
    if (!formFileInput.files || formFileInput.files.length === 0) {
        showError('Please select a file first.');
        return;
    }
    
    const file = formFileInput.files[0];
    if (!file.name.endsWith('.csv')) {
        showError('Please select a CSV file.');
        return;
    }
    
    loading.style.display = 'block';
    errorSection.style.display = 'none';
    submitBtn.disabled = true;
    submitBtn.textContent = 'Processing...';
    
    const formData = new FormData();
    formData.append('file', file);
    
    try {
        const response = await fetch('/upload', {
            method: 'POST',
            body: formData
        });
        
        const data = await response.json();
        
        if (!response.ok) {
            throw new Error(data.error || 'Upload failed');
        }
        
        // Display results on same page
        allResults = data.results || [];
        displayStats(data.stats || {});
        displayResults(allResults);
        
        // Scroll to results
        statsSection.scrollIntoView({ behavior: 'smooth' });
        
    } catch (error) {
        showError('Error: ' + error.message);
    } finally {
        loading.style.display = 'none';
        submitBtn.disabled = false;
        submitBtn.textContent = 'Analyze Logs';
    }
});

function displayStats(stats) {
    document.getElementById('totalRequests').textContent = stats.total || 0;
    document.getElementById('normalCount').textContent = stats.normal || 0;
    document.getElementById('attemptedCount').textContent = stats.attempted || 0;
    document.getElementById('successfulCount').textContent = stats.successful || 0;
    statsSection.style.display = 'block';
}

function displayResults(results) {
    if (results.length === 0) {
        resultsBody.innerHTML = '';
        noResults.style.display = 'block';
        resultsSection.style.display = 'block';
        return;
    }
    
    noResults.style.display = 'none';
    resultsBody.innerHTML = results.map(result => `
        <tr>
            <td>${result.row}</td>
            <td>${escapeHtml(result.method || '')}</td>
            <td class="url-cell" title="${escapeHtml(result.url)}">${escapeHtml(result.url)}</td>
            <td>${result.status_code || 'N/A'}</td>
            <td><span class="classification-${result.classification.toLowerCase().replace(/\s+/g, '-')}">${result.classification}</span></td>
            <td class="attack-type">${result.attack_type || 'None'}</td>
            <td class="severity-${result.severity.toLowerCase()}">${result.severity}</td>
            <td class="indicators" title="${escapeHtml(result.indicators.join(', '))}">${escapeHtml(result.indicators.join(', ') || 'None')}</td>
        </tr>
    `).join('');
    
    resultsSection.style.display = 'block';
}

function escapeHtml(text) {
    if (text === null || text === undefined) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// Filtering and searching
function applyFilters() {
    const searchTerm = searchInput.value.toLowerCase();
    const classificationFilter = filterClassification.value;
    const severityFilter = filterSeverity.value;
    
    filteredResults = allResults.filter(result => {
        const matchesSearch = !searchTerm || (result.url && result.url.toLowerCase().includes(searchTerm));
        const matchesClassification = !classificationFilter || result.classification === classificationFilter;
        const matchesSeverity = !severityFilter || result.severity === severityFilter;
        
        return matchesSearch && matchesClassification && matchesSeverity;
    });
    
    displayResults(filteredResults);
}

if (searchInput) searchInput.addEventListener('input', applyFilters);
if (filterClassification) filterClassification.addEventListener('change', applyFilters);
if (filterSeverity) filterSeverity.addEventListener('change', applyFilters);

// Export functionality
if (exportBtn) {
    exportBtn.addEventListener('click', () => {
        const resultsToExport = filteredResults.length > 0 ? filteredResults : allResults;
        
        if (resultsToExport.length === 0) {
            alert('No results to export');
            return;
        }
        
        const headers = ['Row', 'URL', 'Status Code', 'Classification', 'Attack Type', 'Severity', 'Indicators'];
        const rows = resultsToExport.map(r => [
            r.row,
            r.url,
            r.status_code || '',
            r.classification,
            r.attack_type || '',
            r.severity,
            r.indicators.join('; ')
        ]);
        
        const csvContent = [
            headers.join(','),
            ...rows.map(row => row.map(cell => `"${String(cell).replace(/"/g, '""')}"`).join(','))
        ].join('\n');
        
        const blob = new Blob([csvContent], { type: 'text/csv' });
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `attack_analysis_${new Date().toISOString().split('T')[0]}.csv`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        window.URL.revokeObjectURL(url);
    });
}

function showError(message) {
    document.getElementById('errorText').textContent = message;
    errorSection.style.display = 'block';
    loading.style.display = 'none';
}
