// SAFECLICK - Improved Dashboard with ML Integration
class SafeClickDashboardImproved {
    constructor() {
        this.siteHistory = [];
        this.stats = {};
        this.charts = {};
        this.isLoading = false;
        this.init();
    }

    async init() {
        try {
            this.showLoading();
            await this.loadData();
            this.setupEventListeners();
            await this.initializeCharts();
            this.updateOverview();
            this.populateHistoryTable();
            this.generateDailyReport();
            this.hideLoading();
        } catch (error) {
            console.error('Dashboard initialization error:', error);
            this.hideLoading();
            this.showError('Failed to load dashboard. Please refresh the page.');
        }
    }

    showLoading() {
        this.isLoading = true;
        const loadingOverlay = document.getElementById('loadingOverlay');
        if (loadingOverlay) {
            loadingOverlay.style.display = 'flex';
        }
    }

    hideLoading() {
        this.isLoading = false;
        const loadingOverlay = document.getElementById('loadingOverlay');
        if (loadingOverlay) {
            loadingOverlay.style.display = 'none';
        }
    }

    showError(message) {
        const notification = document.createElement('div');
        notification.className = 'notification error';
        notification.textContent = message;
        document.body.appendChild(notification);
        
        setTimeout(() => {
            if (document.body.contains(notification)) {
                document.body.removeChild(notification);
            }
        }, 5000);
    }

    async loadData() {
        try {
            const result = await chrome.storage.local.get(['siteHistory', 'stats']);
            this.siteHistory = result.siteHistory || [];
            this.stats = result.stats || {
                sitesChecked: 0,
                threatsBlocked: 0,
                todayVisits: 0
            };
            console.log(`Loaded ${this.siteHistory.length} site records`);
        } catch (error) {
            console.error('Error loading data:', error);
            this.siteHistory = [];
            this.stats = { sitesChecked: 0, threatsBlocked: 0, todayVisits: 0 };
        }
    }

    setupEventListeners() {
        // Refresh button
        const refreshBtn = document.getElementById('refreshBtn');
        if (refreshBtn) {
            refreshBtn.addEventListener('click', () => this.refreshData());
        }

        // Export button
        const exportBtn = document.getElementById('exportBtn');
        if (exportBtn) {
            exportBtn.addEventListener('click', () => this.exportReport());
        }

        // Filter controls
        const threatFilter = document.getElementById('threatFilter');
        if (threatFilter) {
            threatFilter.addEventListener('change', () => this.filterHistoryTable());
        }

        const dateFilter = document.getElementById('dateFilter');
        if (dateFilter) {
            dateFilter.addEventListener('change', () => this.filterHistoryTable());
        }

        // Generate report button
        const generateReportBtn = document.getElementById('generateReportBtn');
        if (generateReportBtn) {
            generateReportBtn.addEventListener('click', () => this.generateDailyReport());
        }
    }

    async refreshData() {
        if (this.isLoading) return;
        
        try {
            this.showLoading();
            await this.loadData();
            this.updateOverview();
            this.updateCharts();
            this.populateHistoryTable();
            this.generateDailyReport();
        } catch (error) {
            console.error('Error refreshing data:', error);
            this.showError('Failed to refresh data');
        } finally {
            this.hideLoading();
        }
    }

    updateOverview() {
        try {
            const today = new Date().toDateString();
            const todaySites = this.siteHistory.filter(site => 
                new Date(site.timestamp).toDateString() === today
            );

            const safeCount = todaySites.filter(site => site.threatLevel === 'safe').length;
            const suspiciousCount = todaySites.filter(site => 
                site.threatLevel === 'medium' || site.threatLevel === 'suspicious'
            ).length;
            const phishingCount = todaySites.filter(site => 
                site.threatLevel === 'high' || site.threatLevel === 'blocked'
            ).length;

            // Update DOM elements safely
            const safeSitesEl = document.getElementById('safeSites');
            const suspiciousSitesEl = document.getElementById('suspiciousSites');
            const phishingSitesEl = document.getElementById('phishingSites');
            const totalSitesEl = document.getElementById('totalSites');

            if (safeSitesEl) safeSitesEl.textContent = safeCount;
            if (suspiciousSitesEl) suspiciousSitesEl.textContent = suspiciousCount;
            if (phishingSitesEl) phishingSitesEl.textContent = phishingCount;
            if (totalSitesEl) totalSitesEl.textContent = this.siteHistory.length;
        } catch (error) {
            console.error('Error updating overview:', error);
        }
    }

    async initializeCharts() {
        try {
            await this.initThreatPieChart();
            await this.initDailyActivityChart();
            await this.initWeeklyTrendChart();
            await this.initThreatDistributionChart();
            await this.initWeeklySecurityTrendChart();
        } catch (error) {
            console.error('Error initializing charts:', error);
        }
    }

    async initThreatPieChart() {
        const canvas = document.getElementById('threatPieChart');
        if (!canvas) return;

        const ctx = canvas.getContext('2d');
        
        this.charts.threatPie = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: ['Safe Sites', 'Suspicious Sites', 'Phishing Sites'],
                datasets: [{
                    data: [0, 0, 0],
                    backgroundColor: ['#10b981', '#f59e0b', '#ef4444'],
                    borderWidth: 0,
                    hoverOffset: 4
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: {
                            padding: 20,
                            usePointStyle: true,
                            font: { size: 12 }
                        }
                    },
                    tooltip: {
                        callbacks: {
                            label: function(context) {
                                const label = context.label || '';
                                const value = context.parsed;
                                const total = context.dataset.data.reduce((a, b) => a + b, 0);
                                const percentage = total > 0 ? ((value / total) * 100).toFixed(1) : 0;
                                return `${label}: ${value} (${percentage}%)`;
                            }
                        }
                    }
                }
            }
        });

        this.updateThreatPieChart();
    }

    async initDailyActivityChart() {
        const canvas = document.getElementById('dailyActivityChart');
        if (!canvas) return;

        const ctx = canvas.getContext('2d');
        
        this.charts.dailyActivity = new Chart(ctx, {
            type: 'line',
            data: {
                labels: this.getLast7Days(),
                datasets: [{
                    label: 'Sites Visited',
                    data: this.getDailyActivityData(),
                    borderColor: '#667eea',
                    backgroundColor: 'rgba(102, 126, 234, 0.1)',
                    borderWidth: 3,
                    fill: true,
                    tension: 0.4
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { display: false } },
                scales: {
                    y: {
                        beginAtZero: true,
                        grid: { color: 'rgba(0, 0, 0, 0.1)' }
                    },
                    x: { grid: { display: false } }
                }
            }
        });
    }

    async initWeeklyTrendChart() {
        const canvas = document.getElementById('weeklyTrendChart');
        if (!canvas) return;

        const ctx = canvas.getContext('2d');
        
        this.charts.weeklyTrend = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: this.getLast7Days(),
                datasets: [
                    {
                        label: 'Safe Sites',
                        data: this.getWeeklyTrendData('safe'),
                        backgroundColor: '#10b981',
                        borderColor: '#10b981',
                        borderWidth: 0
                    },
                    {
                        label: 'Suspicious Sites',
                        data: this.getWeeklyTrendData('suspicious'),
                        backgroundColor: '#f59e0b',
                        borderColor: '#f59e0b',
                        borderWidth: 0
                    },
                    {
                        label: 'Phishing Sites',
                        data: this.getWeeklyTrendData('phishing'),
                        backgroundColor: '#ef4444',
                        borderColor: '#ef4444',
                        borderWidth: 0
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'top',
                        labels: { usePointStyle: true, padding: 20 }
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        grid: { color: 'rgba(0, 0, 0, 0.1)' }
                    },
                    x: { grid: { display: false } }
                }
            }
        });
    }

    updateCharts() {
        try {
            this.updateThreatPieChart();
            this.updateDailyActivityChart();
            this.updateWeeklyTrendChart();
            this.updateThreatDistributionChart();
            this.updateWeeklySecurityTrendChart();
        } catch (error) {
            console.error('Error updating charts:', error);
        }
    }

    updateThreatPieChart() {
        if (!this.charts.threatPie) return;

        const today = new Date().toDateString();
        const todaySites = this.siteHistory.filter(site => 
            new Date(site.timestamp).toDateString() === today
        );

        const safeCount = todaySites.filter(site => site.threatLevel === 'safe').length;
        const suspiciousCount = todaySites.filter(site => 
            site.threatLevel === 'medium' || site.threatLevel === 'suspicious'
        ).length;
        const phishingCount = todaySites.filter(site => 
            site.threatLevel === 'high' || site.threatLevel === 'blocked'
        ).length;

        this.charts.threatPie.data.datasets[0].data = [safeCount, suspiciousCount, phishingCount];
        this.charts.threatPie.update('none');
    }

    updateDailyActivityChart() {
        if (!this.charts.dailyActivity) return;
        this.charts.dailyActivity.data.datasets[0].data = this.getDailyActivityData();
        this.charts.dailyActivity.update('none');
    }

    updateWeeklyTrendChart() {
        if (!this.charts.weeklyTrend) return;
        this.charts.weeklyTrend.data.datasets[0].data = this.getWeeklyTrendData('safe');
        this.charts.weeklyTrend.data.datasets[1].data = this.getWeeklyTrendData('suspicious');
        this.charts.weeklyTrend.data.datasets[2].data = this.getWeeklyTrendData('phishing');
        this.charts.weeklyTrend.update('none');
    }

    getLast7Days() {
        const days = [];
        for (let i = 6; i >= 0; i--) {
            const date = new Date();
            date.setDate(date.getDate() - i);
            days.push(date.toLocaleDateString('en-US', { weekday: 'short' }));
        }
        return days;
    }

    getDailyActivityData() {
        const data = [];
        for (let i = 6; i >= 0; i--) {
            const date = new Date();
            date.setDate(date.getDate() - i);
            const dayString = date.toDateString();
            const daySites = this.siteHistory.filter(site => 
                new Date(site.timestamp).toDateString() === dayString
            );
            data.push(daySites.length);
        }
        return data;
    }

    getWeeklyTrendData(type) {
        const data = [];
        for (let i = 6; i >= 0; i--) {
            const date = new Date();
            date.setDate(date.getDate() - i);
            const dayString = date.toDateString();
            const daySites = this.siteHistory.filter(site => 
                new Date(site.timestamp).toDateString() === dayString
            );

            let count = 0;
            switch (type) {
                case 'safe':
                    count = daySites.filter(site => site.threatLevel === 'safe').length;
                    break;
                case 'suspicious':
                    count = daySites.filter(site => 
                        site.threatLevel === 'medium' || site.threatLevel === 'suspicious'
                    ).length;
                    break;
                case 'phishing':
                    count = daySites.filter(site => 
                        site.threatLevel === 'high' || site.threatLevel === 'blocked'
                    ).length;
                    break;
            }
            data.push(count);
        }
        return data;
    }

    populateHistoryTable() {
        try {
            const tbody = document.getElementById('historyTableBody');
            if (!tbody) return;

            tbody.innerHTML = '';

            const sortedHistory = [...this.siteHistory].sort((a, b) => b.timestamp - a.timestamp);
            const filteredHistory = this.filterHistoryData(sortedHistory);

            // Limit to 50 items for performance
            const historyToShow = filteredHistory.slice(0, 50);

            historyToShow.forEach(site => {
                const row = this.createHistoryRow(site);
                tbody.appendChild(row);
            });
        } catch (error) {
            console.error('Error populating history table:', error);
        }
    }

    filterHistoryData(history) {
        const threatFilter = document.getElementById('threatFilter')?.value || 'all';
        const dateFilter = document.getElementById('dateFilter')?.value || '';

        let filtered = history;

        if (threatFilter !== 'all') {
            filtered = filtered.filter(site => {
                switch (threatFilter) {
                    case 'safe': return site.threatLevel === 'safe';
                    case 'suspicious': return site.threatLevel === 'medium' || site.threatLevel === 'suspicious';
                    case 'phishing': return site.threatLevel === 'high' || site.threatLevel === 'blocked';
                    default: return true;
                }
            });
        }

        if (dateFilter) {
            const filterDate = new Date(dateFilter).toDateString();
            filtered = filtered.filter(site => 
                new Date(site.timestamp).toDateString() === filterDate
            );
        }

        return filtered;
    }

    filterHistoryTable() {
        this.populateHistoryTable();
    }

    createHistoryRow(site) {
        const row = document.createElement('tr');
        
        const domain = this.extractDomain(site.url);
        const threatLevel = this.getThreatLevelDisplay(site.threatLevel);
        const threatScore = Math.round((site.threatScore || 0) * 100);
        const dateTime = new Date(site.timestamp).toLocaleString();

        row.innerHTML = `
            <td>
                <div class="site-info">
                    <strong>${domain}</strong>
                    <small>${site.url}</small>
                </div>
            </td>
            <td>
                <span class="threat-badge ${this.getThreatClass(site.threatLevel)}">
                    ${threatLevel}
                </span>
            </td>
            <td>${threatScore}%</td>
            <td>${dateTime}</td>
            <td>
                <button class="btn btn-outline btn-sm" onclick="dashboard.reportSite('${domain}')">
                    <i class="fas fa-flag"></i>
                </button>
            </td>
        `;

        return row;
    }

    extractDomain(url) {
        try {
            const urlObj = new URL(url);
            return urlObj.hostname;
        } catch {
            return 'Unknown';
        }
    }

    getThreatLevelDisplay(level) {
        switch (level) {
            case 'safe': return 'Safe';
            case 'medium': return 'Suspicious';
            case 'suspicious': return 'Suspicious';
            case 'high': return 'Phishing';
            case 'blocked': return 'Blocked';
            default: return 'Unknown';
        }
    }

    getThreatClass(level) {
        switch (level) {
            case 'safe': return 'safe';
            case 'medium': return 'suspicious';
            case 'suspicious': return 'suspicious';
            case 'high': return 'phishing';
            case 'blocked': return 'phishing';
            default: return 'safe';
        }
    }

    async reportSite(domain) {
        try {
            const result = await chrome.storage.local.get(['reportedSites']);
            const reportedSites = result.reportedSites || [];
            
            if (!reportedSites.includes(domain)) {
                reportedSites.push(domain);
                await chrome.storage.local.set({ reportedSites });
                this.showNotification('Site reported successfully!', 'success');
            } else {
                this.showNotification('Site already reported', 'warning');
            }
        } catch (error) {
            console.error('Error reporting site:', error);
            this.showNotification('Error reporting site', 'error');
        }
    }

    generateDailyReport() {
        try {
            const today = new Date();
            const todayString = today.toDateString();
            const todaySites = this.siteHistory.filter(site => 
                new Date(site.timestamp).toDateString() === todayString
            );

            const reportDateEl = document.getElementById('reportDate');
            if (reportDateEl) {
                reportDateEl.textContent = today.toLocaleDateString();
            }

            const totalTime = this.calculateTotalTimeOnline(todaySites);
            const totalTimeEl = document.getElementById('totalTimeOnline');
            if (totalTimeEl) {
                totalTimeEl.textContent = totalTime;
            }

            this.generateSecurityHighlights(todaySites);
            this.generateRecommendations(todaySites);
        } catch (error) {
            console.error('Error generating daily report:', error);
        }
    }

    calculateTotalTimeOnline(sites) {
        if (sites.length === 0) return '0 hours';
        
        const totalMinutes = sites.length * 2;
        const hours = Math.floor(totalMinutes / 60);
        const minutes = totalMinutes % 60;
        
        if (hours > 0) {
            return `${hours}h ${minutes}m`;
        } else {
            return `${minutes}m`;
        }
    }

    generateSecurityHighlights(sites) {
        const highlights = document.getElementById('securityHighlights');
        if (!highlights) return;

        highlights.innerHTML = '';

        const safeCount = sites.filter(site => site.threatLevel === 'safe').length;
        const suspiciousCount = sites.filter(site => 
            site.threatLevel === 'medium' || site.threatLevel === 'suspicious'
        ).length;
        const phishingCount = sites.filter(site => 
            site.threatLevel === 'high' || site.threatLevel === 'blocked'
        ).length;

        const highlightsList = [];

        if (safeCount > 0) highlightsList.push(`Visited ${safeCount} safe websites`);
        if (suspiciousCount > 0) highlightsList.push(`Encountered ${suspiciousCount} suspicious sites`);
        if (phishingCount > 0) highlightsList.push(`Blocked ${phishingCount} phishing attempts`);
        if (sites.length === 0) highlightsList.push('No sites visited today');

        highlightsList.forEach(highlight => {
            const li = document.createElement('li');
            li.textContent = highlight;
            highlights.appendChild(li);
        });
    }

    generateRecommendations(sites) {
        const recommendations = document.getElementById('recommendations');
        if (!recommendations) return;

        recommendations.innerHTML = '';

        const recommendationsList = [];

        const phishingCount = sites.filter(site => 
            site.threatLevel === 'high' || site.threatLevel === 'blocked'
        ).length;

        if (phishingCount > 0) {
            recommendationsList.push('Be extra cautious with suspicious links');
            recommendationsList.push('Enable two-factor authentication on important accounts');
        }

        if (sites.length > 20) {
            recommendationsList.push('Consider taking regular breaks from browsing');
        }

        if (sites.length === 0) {
            recommendationsList.push('Start browsing to see security insights');
        }

        if (recommendationsList.length === 0) {
            recommendationsList.push('Continue practicing safe browsing habits');
            recommendationsList.push('Keep SAFECLICK enabled for protection');
        }

        recommendationsList.forEach(recommendation => {
            const li = document.createElement('li');
            li.textContent = recommendation;
            recommendations.appendChild(li);
        });
    }

    async exportReport() {
        try {
            const report = this.generateExportReport();
            const blob = new Blob([report], { type: 'text/csv' });
            const url = URL.createObjectURL(blob);
            
            const a = document.createElement('a');
            a.href = url;
            a.download = `safeclick-report-${new Date().toISOString().split('T')[0]}.csv`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);

            this.showNotification('Report exported successfully!', 'success');
        } catch (error) {
            console.error('Error exporting report:', error);
            this.showNotification('Error exporting report', 'error');
        }
    }

    generateExportReport() {
        const today = new Date().toDateString();
        const todaySites = this.siteHistory.filter(site => 
            new Date(site.timestamp).toDateString() === today
        );

        let csv = 'Site,Threat Level,Threat Score,Date & Time\n';
        
        todaySites.forEach(site => {
            const domain = this.extractDomain(site.url);
            const threatLevel = this.getThreatLevelDisplay(site.threatLevel);
            const threatScore = Math.round((site.threatScore || 0) * 100);
            const dateTime = new Date(site.timestamp).toLocaleString();
            
            csv += `"${domain}","${threatLevel}",${threatScore},"${dateTime}"\n`;
        });

        return csv;
    }

    showNotification(message, type = 'info') {
        const notification = document.createElement('div');
        notification.className = `notification ${type}`;
        notification.textContent = message;
        
        if (!document.querySelector('#notification-styles')) {
            const style = document.createElement('style');
            style.id = 'notification-styles';
            style.textContent = `
                .notification {
                    position: fixed;
                    top: 20px;
                    right: 20px;
                    background: white;
                    border-radius: 10px;
                    padding: 15px 20px;
                    box-shadow: 0 10px 30px rgba(0, 0, 0, 0.2);
                    z-index: 10000;
                    transform: translateX(400px);
                    transition: transform 0.3s ease;
                    font-family: 'Segoe UI', sans-serif;
                }
                .notification.show {
                    transform: translateX(0);
                }
                .notification.success {
                    border-left: 4px solid #10b981;
                }
                .notification.warning {
                    border-left: 4px solid #f59e0b;
                }
                .notification.error {
                    border-left: 4px solid #ef4444;
                }
                .notification.info {
                    border-left: 4px solid #3b82f6;
                }
            `;
            document.head.appendChild(style);
        }
        
        document.body.appendChild(notification);
        
        setTimeout(() => {
            notification.classList.add('show');
        }, 100);
        
        setTimeout(() => {
            notification.classList.remove('show');
            setTimeout(() => {
                if (document.body.contains(notification)) {
                    document.body.removeChild(notification);
                }
            }, 300);
        }, 3000);
    }

    async initThreatDistributionChart() {
        const canvas = document.getElementById('threatDistributionChart');
        if (!canvas) return;

        const ctx = canvas.getContext('2d');
        
        this.charts.threatDistribution = new Chart(ctx, {
            type: 'doughnut',
            data: this.getThreatDistributionData(),
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: { 
                            usePointStyle: true, 
                            padding: 20,
                            font: { size: 12 }
                        }
                    },
                    tooltip: {
                        callbacks: {
                            label: function(context) {
                                const label = context.label || '';
                                const value = context.parsed;
                                const total = context.dataset.data.reduce((a, b) => a + b, 0);
                                const percentage = ((value / total) * 100).toFixed(1);
                                return `${label}: ${value} (${percentage}%)`;
                            }
                        }
                    }
                }
            }
        });
    }

    async initWeeklySecurityTrendChart() {
        const canvas = document.getElementById('weeklySecurityTrendChart');
        if (!canvas) return;

        const ctx = canvas.getContext('2d');
        
        this.charts.weeklySecurityTrend = new Chart(ctx, {
            type: 'line',
            data: {
                labels: this.getLast7Days(),
                datasets: [{
                    label: 'Security Score',
                    data: this.getWeeklySecurityTrendData(),
                    borderColor: '#667eea',
                    backgroundColor: 'rgba(102, 126, 234, 0.1)',
                    borderWidth: 3,
                    fill: true,
                    tension: 0.4,
                    pointBackgroundColor: '#667eea',
                    pointBorderColor: '#ffffff',
                    pointBorderWidth: 2,
                    pointRadius: 6
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { display: false },
                    tooltip: {
                        callbacks: {
                            label: function(context) {
                                return `Security Score: ${context.parsed.y}%`;
                            }
                        }
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        max: 100,
                        grid: { color: 'rgba(0, 0, 0, 0.1)' },
                        ticks: {
                            callback: function(value) {
                                return value + '%';
                            }
                        }
                    },
                    x: { grid: { display: false } }
                }
            }
        });
    }

    getThreatDistributionData() {
        const threatTypes = {
            'Safe Sites': 0,
            'Suspicious Sites': 0,
            'Phishing Sites': 0,
            'Blocked Sites': 0,
            'Unknown': 0
        };

        this.siteHistory.forEach(site => {
            switch (site.threatLevel) {
                case 'safe':
                    threatTypes['Safe Sites']++;
                    break;
                case 'medium':
                case 'suspicious':
                    threatTypes['Suspicious Sites']++;
                    break;
                case 'high':
                case 'phishing':
                    threatTypes['Phishing Sites']++;
                    break;
                case 'blocked':
                    threatTypes['Blocked Sites']++;
                    break;
                default:
                    threatTypes['Unknown']++;
            }
        });

        const colors = ['#10b981', '#f59e0b', '#ef4444', '#dc2626', '#6b7280'];
        
        return {
            labels: Object.keys(threatTypes),
            datasets: [{
                data: Object.values(threatTypes),
                backgroundColor: colors,
                borderColor: colors.map(color => color + '80'),
                borderWidth: 2,
                hoverOffset: 4
            }]
        };
    }

    getWeeklySecurityTrendData() {
        const data = [];
        for (let i = 6; i >= 0; i--) {
            const date = new Date();
            date.setDate(date.getDate() - i);
            const dayString = date.toDateString();
            const daySites = this.siteHistory.filter(site => 
                new Date(site.timestamp).toDateString() === dayString
            );

            if (daySites.length === 0) {
                data.push(100); // Perfect security score for days with no activity
            } else {
                const safeSites = daySites.filter(site => site.threatLevel === 'safe').length;
                const totalSites = daySites.length;
                const securityScore = Math.round((safeSites / totalSites) * 100);
                data.push(securityScore);
            }
        }
        return data;
    }

    updateThreatDistributionChart() {
        if (!this.charts.threatDistribution) return;
        this.charts.threatDistribution.data = this.getThreatDistributionData();
        this.charts.threatDistribution.update('none');
    }

    updateWeeklySecurityTrendChart() {
        if (!this.charts.weeklySecurityTrend) return;
        this.charts.weeklySecurityTrend.data.datasets[0].data = this.getWeeklySecurityTrendData();
        this.charts.weeklySecurityTrend.update('none');
    }
}

// Initialize dashboard when DOM is loaded
let dashboard;
document.addEventListener('DOMContentLoaded', () => {
    dashboard = new SafeClickDashboardImproved();
});
