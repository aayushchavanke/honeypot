let chartInstance = null;
let currentRange = 'today';
let specificDate = '';

// --- UI LOGIC ---
function setRange(range) {
    currentRange = range;
    specificDate = ''; // Clear date if range button clicked
    
    // UI Update
    document.querySelectorAll('.btn-group .btn').forEach(btn => btn.classList.remove('active'));
    // Find button with onclick matching range and add active (simplified)
    event.target.classList.add('active');
    
    document.getElementById('rangeLabel').textContent = "Filter: " + range.toUpperCase();
    document.getElementById('dateInput').value = ''; // Reset date picker
    fetchStats();
}

function setDate(dateStr) {
    specificDate = dateStr;
    currentRange = 'custom';
    
    // UI Update
    document.querySelectorAll('.btn-group .btn').forEach(btn => btn.classList.remove('active'));
    document.getElementById('rangeLabel').textContent = "Filter: " + dateStr;
    fetchStats();
}

function downloadReport() {
    let url = `/download_report?time_range=${currentRange}`;
    if (specificDate) url += `&date=${specificDate}`;
    window.location.href = url;
}

// --- CHART & DATA ---
async function fetchStats() {
    try {
        let url = `/api/stats?time_range=${currentRange}`;
        if (specificDate) url += `&date=${specificDate}`;
        
        const response = await fetch(url);
        const data = await response.json();
        updateUI(data);
    } catch (error) { console.error('Error:', error); }
}

function getBadgeClass(type) {
    const map = { 'SQLi': 'badge-sqli', 'XSS': 'badge-xss', 'Cmdi': 'badge-cmdi', 'LFI': 'badge-lfi', 'RCE': 'badge-rce', 'DoS': 'badge-dos', 'BruteForce': 'badge-bf', 'Scanner': 'badge-scan' };
    return map[type] || 'bg-secondary';
}

function updateUI(data) {
    // 1. Update Logs Table
    const tbody = document.getElementById('logTable');
    let rowsHtml = '';
    
    if(data.logs.length === 0) rowsHtml = '<tr><td colspan="6" class="text-center text-muted p-4">No data found for this period.</td></tr>';
    
    data.logs.forEach(log => {
        let connType = log.connection_type || 'Unknown';
        let connBadge = 'bg-secondary';
        if(connType.includes('VPN')) connBadge = 'bg-danger';
        else if(connType.includes('TOR')) connBadge = 'bg-warning text-dark';
        else if(connType.includes('RESIDENTIAL')) connBadge = 'bg-success';

        rowsHtml += `
            <tr>
                <td class="text-secondary small">${new Date(log.timestamp).toLocaleTimeString()}</td>
                <td><span class="badge ${getBadgeClass(log.attack_type)}">${log.attack_type}</span></td>
                <td><div class="fw-bold text-white">${log.country || 'Unknown'}</div><div class="small text-muted">${log.city || 'Unknown'}</div></td>
                <td class="small font-monospace text-info">${log.rdns || '-'}</td>
                <td><span class="badge ${connBadge}">${connType}</span></td>
                <td class="font-monospace text-warning small text-break" style="max-width: 200px;">${log.payload ? log.payload.substring(0, 50) : ''}</td>
            </tr>`;
    });
    tbody.innerHTML = rowsHtml;

    // 2. Update Header Stats
    document.getElementById('statTotal').innerText = data.logs.length;
    
    // 3. Update Chart (Without Blinking)
    updateChart(data.counts);
}

function updateChart(counts) {
    const ctx = document.getElementById('attackChart').getContext('2d');
    const total = counts.reduce((a, b) => a + b, 0);
    const dataValues = total === 0 ? [1] : counts;
    const colors = total === 0 ? ['#333'] : ['#ef4444', '#eab308', '#ffffff', '#6b7280', '#a855f7', '#be123c', '#f97316', '#14b8a6'];

    if (chartInstance) {
        // Update existing chart data to animate smoothly
        chartInstance.data.datasets[0].data = dataValues;
        chartInstance.data.datasets[0].backgroundColor = colors;
        chartInstance.update();
    } else {
        // Create fresh if doesn't exist
        chartInstance = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: ['SQLi', 'XSS', 'Cmdi', 'LFI', 'RCE', 'DoS', 'Brute', 'Scanner'],
                datasets: [{
                    data: dataValues,
                    backgroundColor: colors,
                    borderWidth: 0,
                    hoverOffset: 20 // Dynamic Pop-out
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                animation: { duration: 800, easing: 'easeOutQuart' },
                plugins: { legend: { position: 'bottom', labels: { color: '#cbd5e1' } } }
            }
        });
    }
}

// Auto-refresh
setInterval(fetchStats, 2000);
fetchStats();