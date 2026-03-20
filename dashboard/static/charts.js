const socket = io();

// Chart Theme overrides for Dark Mode
Chart.defaults.color = '#94a3b8';
Chart.defaults.font.family = 'Inter';

// 1. Initialise Pie Chart
const ctxPie = document.getElementById('pieChart').getContext('2d');
const pieChart = new Chart(ctxPie, {
    type: 'doughnut',
    data: {
        labels: [],
        datasets: [{
            data: [],
            backgroundColor: [
                '#3b82f6', '#ef4444', '#10b981', '#f59e0b', '#8b5cf6', '#ec4899', '#14b8a6'
            ],
            borderWidth: 0,
            hoverOffset: 4
        }]
    },
    options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
            legend: { position: 'right' }
        },
        cutout: '70%'
    }
});

// 2. Initialise Bar Chart
const ctxBar = document.getElementById('barChart').getContext('2d');
const barChart = new Chart(ctxBar, {
    type: 'bar',
    data: {
        labels: ['Forwarded', 'Dropped'],
        datasets: [{
            label: 'Packets',
            data: [0, 0],
            backgroundColor: [
                'rgba(16, 185, 129, 0.8)', // Emerald
                'rgba(239, 68, 68, 0.8)'   // Red
            ],
            borderRadius: 6
        }]
    },
    options: {
        responsive: true,
        maintainAspectRatio: false,
        scales: {
            y: { beginAtZero: true, grid: { color: 'rgba(51, 65, 85, 0.5)' } },
            x: { grid: { display: false } }
        },
        plugins: { legend: { display: false } }
    }
});

function formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024, sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

// 3. Listen for WebSocket updates
socket.on('stats_update', function(data) {
    // Update Stats
    document.getElementById('stat-packets').innerText = data.total_packets;
    document.getElementById('stat-bytes').innerText = formatBytes(data.bytes);
    document.getElementById('stat-speed').innerText = data.speed + " pkt/s";
    document.getElementById('stat-dropped').innerText = data.dropped;

    // Update Bar Chart
    barChart.data.datasets[0].data = [data.forwarded, data.dropped];
    barChart.update();

    // Update Pie Chart Data
    const appLabels = Object.keys(data.app_breakdown);
    const appData = Object.values(data.app_breakdown);
    
    let isDifferent = false;
    if (pieChart.data.labels.length !== appLabels.length) isDifferent = true;
    else {
        for(let i=0; i<appLabels.length; i++) {
            if (pieChart.data.labels[i] !== appLabels[i] || pieChart.data.datasets[0].data[i] !== appData[i]) {
                isDifferent = true; break;
            }
        }
    }

    if (isDifferent) {
        pieChart.data.labels = appLabels;
        pieChart.data.datasets[0].data = appData;
        pieChart.update();
    }

    // Update SNI Table
    const tableHtml = data.snis.map(s => `
        <tr class="transition hover:bg-slate-800/50">
            <td class="py-3 pr-4 font-mono text-blue-300 truncate max-w-[200px]" title="${s.sni}">${s.sni}</td>
            <td class="py-3 px-4 text-emerald-400 font-medium">${s.app}</td>
            <td class="py-3 px-4 text-right tabular-nums text-slate-300">${(s.conf * 100).toFixed(1)}%</td>
        </tr>
    `).join('');
    document.getElementById('table-snis').innerHTML = tableHtml || '<tr><td colspan="3" class="py-4 text-center text-slate-500 italic">No SNIs detected yet</td></tr>';

    // Update Alerts Box
    const alertsHtml = data.alerts.map(a => `
        <div class="p-3 rounded-lg bg-red-500/10 border border-red-500/20 text-red-200 text-sm font-mono flex items-start">
            <svg class="w-5 h-5 text-red-400 mr-2 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path></svg>
            ${a}
        </div>
    `).reverse().join('');
    document.getElementById('alert-box').innerHTML = alertsHtml || '<div class="text-slate-500 italic text-center py-4">All systems clear</div>';
});
