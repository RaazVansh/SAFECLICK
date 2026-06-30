// Phish Shield - Improved Dashboard Script with ML Integration
class SafeClickDashboard {
    constructor() {
        this.siteHistory = [];
        this.stats = {};
        this.charts = {};
        this.mlModel = null;
        this.isLoading = false;
        this.debounceTimer = null;
        this.init();
    }

    async init() {
        try {
            this.showLoading();
            
            // Initialize ML model
            await this.initializeMLModel();
            
            // Load data with better error handling
            await this.loadData();
            
            // Setup event listeners
            this.setupEventListeners();
            
            // Initialize charts with lazy loading
            await this.initializeCharts();
            
            // Update UI components
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

    async initializeMLModel() {
        try {
            // Import and initialize ML model
            const { SafeClickMLModel } = await import('./ml-model.js');
            this.mlModel = new SafeClickMLModel();
            console.log('ML Model initialized for dashboard');
        } catch (error) {
            console.error('Error initializing ML model:', error);
            // Continue without ML model
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
            // Load data from Chrome storage with timeout
            const dataPromise = chrome.storage.local.get(['siteHistory', 'stats']);
            const timeoutPromise = new Promise((_, reject) => 
                setTimeout(() => reject(new Error('Data loading timeout')), 5000)
            );
            
            const result = await Promise.race([dataPromise, timeoutPromise]);
            
            this.siteHistory = result.siteHistory || [];
            this.stats = result.stats || {
                sitesChecked: 0,
                threatsBlocked: 0,
                todayVisits: 0
            };
            
            console.log(`Loaded ${this.siteHistory.length} site records`);
        } catch (error) {
            console.error('Error loading data:', error);
            // Use default data
            this.siteHistory = [];
            this.stats = {
                sitesChecked: 0,
                threatsBlocked: 0,
                todayVisits: 0
            };
        }
    }

    setupEventListeners() {
        // Debounced refresh button
        const refreshBtn = document.getElementById('refreshBtn');
        if (refreshBtn) {
            refreshBtn.addEventListener('click', () => {
                this.debouncedRefresh();
            });
        }

        // Export button
        const exportBtn = document.getElementById('exportBtn');
        if (exportBtn) {
            exportBtn.addEventListener('click', () => {
                this.exportReport();
            });
        }

        // Filter controls with debouncing
        const threatFilter = document.getElementById('threatFilter');
        if (threatFilter) {
            threatFilter.addEventListener('change', () => {
                this.debouncedFilter();
            });
        }

        const dateFilter = document.getElementById('dateFilter');
        if (dateFilter) {
            dateFilter.addEventListener('change', () => {
                this.debouncedFilter();
            });
        }

        // Generate report button
        const generateReportBtn = document.getElementById('generateReportBtn');
        if (generateReportBtn) {
            generateReportBtn.addEventListener('change', () => {
                this.generateDailyReport();
            });
        }

        // ML Model update button
        const updateModelBtn = document.getElementById('updateModelBtn');
        if (updateModelBtn) {
            updateModelBtn.addEventListener('click', () => {
                this.updateMLModel();
            });
        }
    }

    debouncedRefresh() {
        if (this.debounceTimer) {
            clearTimeout(this.debounceTimer);
        }
        this.debounceTimer = setTimeout(() => {
            this.refreshData();
        }, 300);
    }

    debouncedFilter() {
        if (this.debounceTimer) {
            clearTimeout(this.debounceTimer);
        }
        this.debounceTimer = setTimeout(() => {
            this.filterHistoryTable();
        }, 300);
    }

    async refreshData() {
        if (this.isLoading) return;
        
        try {
            this.showLoading();
            await this.loadData();
            this.updateOverview();
            await this.updateCharts();
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

            // Update ML model stats if available
            if (this.mlModel) {
                this.updateMLStats();
            }
        } catch (error) {
            console.error('Error updating overview:', error);
        }
    }

    updateMLStats() {
        try {
            const stats = this.mlModel.getModelStats();
            const mlStatsEl = document.getElementById('mlStats');
            if (mlStatsEl) {
                mlStatsEl.innerHTML = `
                    <div class="ml-stat">
                        <span class="stat-label">Algorithm:</span>
                        <span class="stat-value">${stats.algorithm}</span>
                    </div>
                    <div class="ml-stat">
                        <span class="stat-label">Model Version:</span>
                        <span class="stat-value">${stats.version}</span>
                    </div>
                    <div class="ml-stat">
                        <span class="stat-label">Training Accuracy:</span>
                        <span class="stat-value">${stats.accuracy ? (stats.accuracy * 100).toFixed(1) + '%' : 'N/A'}</span>
                    </div>
                    <div class="ml-stat">
                        <span class="stat-label">Phishing Dataset:</span>
                        <span class="stat-value">${stats.datasetSize} URLs</span>
                    </div>
                    <div class="ml-stat">
                        <span class="stat-label">Features:</span>
                        <span class="stat-value">${stats.features} dimensions</span>
                    </div>
                `;
            }
        } catch (error) {
            console.error('Error updating ML stats:', error);
        }
    }

    async initializeCharts() {
        try {
            // Initialize charts with lazy loading
            await this.initThreatPieChart();
            await this.initDailyActivityChart();
            await this.initWeeklyTrendChart();
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
                    backgroundColor: [
                        '#10b981',
                        '#f59e0b',
                        '#ef4444'
                    ],
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
                            font: {
                                size: 12
                            }
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

        // Update with actual data
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
                plugins: {
                    legend: {
                        display: false
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        grid: {
                            color: 'rgba(0, 0, 0, 0.1)'
                        }
                    },
                    x: {
                        grid: {
                            display: false
                        }
                    }
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
                        labels: {
                            usePointStyle: true,
                            padding: 20
                        }
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        grid: {
                            color: 'rgba(0, 0, 0, 0.1)'
                        }
                    },
                    x: {
                        grid: {
                            display: false
                        }
                    }
                }
            }
        });
    }

    updateCharts() {
        try {
            this.updateThreatPieChart();
            this.updateDailyActivityChart();
            this.updateWeeklyTrendChart();
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
        this.charts.threatPie.update('none'); // Use 'none' for better performance
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

            // Use virtual scrolling for large datasets
            const displayLimit = 50;
            const historyToShow = filteredHistory.slice(0, displayLimit);

            historyToShow.forEach(site => {
                const row = this.createHistoryRow(site);
                tbody.appendChild(row);
            });

            // Show load more button if needed
            this.updateLoadMoreButton(filteredHistory.length, displayLimit);
        } catch (error) {
            console.error('Error populating history table:', error);
        }
    }

    updateLoadMoreButton(totalCount, displayedCount) {
        const loadMoreBtn = document.getElementById('loadMoreBtn');
        if (loadMoreBtn) {
            if (totalCount > displayedCount) {
                loadMoreBtn.style.display = 'block';
                loadMoreBtn.textContent = `Load More (${totalCount - displayedCount} remaining)`;
            } else {
                loadMoreBtn.style.display = 'none';
            }
        }
    }

    filterHistoryData(history) {
        const threatFilter = document.getElementById('threatFilter')?.value || 'all';
        const dateFilter = document.getElementById('dateFilter')?.value || '';

        let filtered = history;

        // Filter by threat level
        if (threatFilter !== 'all') {
            filtered = filtered.filter(site => {
                switch (threatFilter) {
                    case 'safe':
                        return site.threatLevel === 'safe';
                    case 'suspicious':
                        return site.threatLevel === 'medium' || site.threatLevel === 'suspicious';
                    case 'phishing':
                        return site.threatLevel === 'high' || site.threatLevel === 'blocked';
                    default:
                        return true;
                }
            });
        }

        // Filter by date
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

    async updateMLModel() {
        if (!this.mlModel) {
            this.showNotification('ML Model not available', 'error');
            return;
        }

        try {
            this.showNotification('Updating ML model...', 'info');
            await this.mlModel.updateModel();
            this.updateMLStats();
            this.showNotification('ML Model updated successfully!', 'success');
        } catch (error) {
            console.error('Error updating ML model:', error);
            this.showNotification('Failed to update ML model', 'error');
        }
    }

    generateDailyReport() {
        try {
            const today = new Date();
            const todayString = today.toDateString();
            const todaySites = this.siteHistory.filter(site => 
                new Date(site.timestamp).toDateString() === todayString
            );

            // Update report date
            const reportDateEl = document.getElementById('reportDate');
            if (reportDateEl) {
                reportDateEl.textContent = today.toLocaleDateString();
            }

            // Calculate total time online
            const totalTime = this.calculateTotalTimeOnline(todaySites);
            const totalTimeEl = document.getElementById('totalTimeOnline');
            if (totalTimeEl) {
                totalTimeEl.textContent = totalTime;
            }

            // Generate security highlights
            this.generateSecurityHighlights(todaySites);

            // Generate recommendations
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

        if (safeCount > 0) {
            highlightsList.push(`Visited ${safeCount} safe websites`);
        }

        if (suspiciousCount > 0) {
            highlightsList.push(`Encountered ${suspiciousCount} suspicious sites`);
        }

        if (phishingCount > 0) {
            highlightsList.push(`Blocked ${phishingCount} phishing attempts`);
        }

        if (sites.length === 0) {
            highlightsList.push('No sites visited today');
        }

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
            recommendationsList.push('Keep Phish Shield enabled for protection');
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
            a.download = `phish-shield-report-${new Date().toISOString().split('T')[0]}.csv`;
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
        
        // Add styles if not already present
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
}

// Initialize dashboard when DOM is loaded
let dashboard;
document.addEventListener('DOMContentLoaded', () => {
    dashboard = new SafeClickDashboard();
});
