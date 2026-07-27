document.addEventListener('DOMContentLoaded', () => {
    const data = window.metricsData || {};
    const chartDefaults = {
        color: '#9ca3af',
        borderColor: '#374151',
    };

    Chart.defaults.color = chartDefaults.color;
    Chart.defaults.borderColor = chartDefaults.borderColor;

    const severityCtx = document.getElementById('severityChart');
    if (severityCtx && data.alerts_by_severity) {
        new Chart(severityCtx, {
            type: 'doughnut',
            data: {
                labels: Object.keys(data.alerts_by_severity),
                datasets: [{
                    data: Object.values(data.alerts_by_severity),
                    backgroundColor: ['#ef4444', '#f59e0b', '#3b82f6'],
                }],
            },
            options: { responsive: true },
        });
    }

    const latencyCtx = document.getElementById('latencyChart');
    if (latencyCtx && data.latency_by_scenario) {
        new Chart(latencyCtx, {
            type: 'bar',
            data: {
                labels: Object.keys(data.latency_by_scenario),
                datasets: [{
                    label: 'Latence moyenne (ms)',
                    data: Object.values(data.latency_by_scenario),
                    backgroundColor: '#3b82f6',
                }],
            },
            options: {
                responsive: true,
                scales: { y: { beginAtZero: true } },
            },
        });
    }

    const timelineCtx = document.getElementById('timelineChart');
    if (timelineCtx && data.alerts_by_hour) {
        const sorted = Object.entries(data.alerts_by_hour).sort((a, b) => a[0].localeCompare(b[0]));
        new Chart(timelineCtx, {
            type: 'line',
            data: {
                labels: sorted.map(e => e[0]),
                datasets: [{
                    label: 'Alertes',
                    data: sorted.map(e => e[1]),
                    borderColor: '#10b981',
                    fill: true,
                    backgroundColor: 'rgba(16, 185, 129, 0.1)',
                }],
            },
            options: { responsive: true, scales: { y: { beginAtZero: true, ticks: { stepSize: 1 } } } },
        });
    }
});
