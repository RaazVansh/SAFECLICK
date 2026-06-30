// Phish Shield - AI Phishing Detection Popup Script
class SafeClickPopup {
    constructor() {
        this.currentTab = null;
        this.stats = {
            sitesChecked: 0,
            threatsBlocked: 0,
            todayVisits: 0
        };
        this.threatChart = null;
        this.init();
    }

    async init() {
        await this.loadStats();
        await this.getCurrentTab();
        this.setupEventListeners();
        this.analyzeCurrentSite();
        this.initChart();
        this.updateUI();
    }

    async getCurrentTab() {
        try {
            const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
            this.currentTab = tab;
            document.getElementById('currentSite').textContent = this.extractDomain(tab.url);
        } catch (error) {
            console.error('Error getting current tab:', error);
        }
    }

    extractDomain(url) {
        try {
            const urlObj = new URL(url);
            return urlObj.hostname;
        } catch {
            return 'Unknown site';
        }
    }

    async loadStats() {
        try {
            const result = await chrome.storage.local.get(['stats', 'siteHistory']);
            this.stats = result.stats || this.stats;
            
            // Calculate today's visits
            const today = new Date().toDateString();
            const siteHistory = result.siteHistory || [];
            this.stats.todayVisits = siteHistory.filter(site => 
                new Date(site.timestamp).toDateString() === today
            ).length;
        } catch (error) {
            console.error('Error loading stats:', error);
        }
    }

    async analyzeCurrentSite() {
        if (!this.currentTab || !this.currentTab.url) return;

        const url = this.currentTab.url;
        const domain = this.extractDomain(url);
        
        // Update status to analyzing
        this.updateSiteStatus('analyzing', 'Analyzing site for threats...');

        try {
            const result = await this.detectPhishing(url);
            const threatScore = result.threatScore ?? result;

            if (threatScore > 0.5) {
                this.updateSiteStatus('danger', 'High risk phishing site detected!');
                this.showMLDetails(result);
                await this.recordThreat(url, 'high');
            } else if (threatScore > 0.3) {
                this.updateSiteStatus('warning', 'Suspicious site detected');
                this.showMLDetails(result);
                await this.recordThreat(url, 'medium');
            } else {
                this.updateSiteStatus('safe', 'Site appears safe');
                await this.recordSafeSite(url);
            }

            // Update stats
            this.stats.sitesChecked++;
            await this.saveStats();
            this.updateStatsDisplay();

        } catch (error) {
            console.error('Error analyzing site:', error);
            this.updateSiteStatus('warning', 'Unable to analyze site');
        }
    }

    async detectPhishing(url) {
        return new Promise((resolve) => {
            chrome.runtime.sendMessage({ action: 'analyzeSite', url }, (response) => {
                if (chrome.runtime.lastError || !response) {
                    resolve({ threatScore: 0.5, threatLevel: 'unknown' });
                    return;
                }
                resolve(response);
            });
        });
    }

    showMLDetails(result) {
        if (!result || typeof result !== 'object') return;
        const confidence = result.confidence != null
            ? ` (${Math.round(result.confidence * 100)}% confidence)`
            : '';
        const mlNote = result.inDataset ? ' — matched phishing dataset' : '';
        const el = document.getElementById('statusText');
        if (el && result.threatLevel) {
            el.textContent += confidence + mlNote;
        }
    }

    updateSiteStatus(status, message) {
        const statusIcon = document.getElementById('statusIcon');
        const statusText = document.getElementById('statusText');
        
        statusIcon.className = 'status-icon';
        statusText.textContent = message;
        
        switch (status) {
            case 'safe':
                statusIcon.classList.add('safe');
                statusIcon.innerHTML = '<i class="fas fa-shield-check"></i>';
                break;
            case 'warning':
                statusIcon.classList.add('warning');
                statusIcon.innerHTML = '<i class="fas fa-exclamation-triangle"></i>';
                break;
            case 'danger':
                statusIcon.classList.add('danger');
                statusIcon.innerHTML = '<i class="fas fa-times-circle"></i>';
                break;
            case 'analyzing':
                statusIcon.innerHTML = '<div class="loading"></div>';
                break;
        }
    }

    async blockSite() {
        if (!this.currentTab) return;
        
        // Show blocking notification
        this.showNotification('danger', 'Phishing site blocked! This site has been reported as malicious.');
        
        // In a real implementation, you would redirect to a warning page
        // For now, we'll just update the stats
        this.stats.threatsBlocked++;
        await this.saveStats();
    }

    async recordThreat(url, level) {
        const siteRecord = {
            url: url,
            domain: this.extractDomain(url),
            threatLevel: level,
            timestamp: Date.now(),
            type: 'threat'
        };
        
        await this.addToSiteHistory(siteRecord);
    }

    async recordSafeSite(url) {
        const siteRecord = {
            url: url,
            domain: this.extractDomain(url),
            threatLevel: 'safe',
            timestamp: Date.now(),
            type: 'safe'
        };
        
        await this.addToSiteHistory(siteRecord);
    }

    async addToSiteHistory(record) {
        try {
            const result = await chrome.storage.local.get(['siteHistory']);
            const siteHistory = result.siteHistory || [];
            siteHistory.push(record);
            
            // Keep only last 1000 records
            if (siteHistory.length > 1000) {
                siteHistory.splice(0, siteHistory.length - 1000);
            }
            
            await chrome.storage.local.set({ siteHistory });
        } catch (error) {
            console.error('Error saving site history:', error);
        }
    }

    async saveStats() {
        try {
            await chrome.storage.local.set({ stats: this.stats });
        } catch (error) {
            console.error('Error saving stats:', error);
        }
    }

    updateStatsDisplay() {
        document.getElementById('sitesChecked').textContent = this.stats.sitesChecked;
        document.getElementById('threatsBlocked').textContent = this.stats.threatsBlocked;
        document.getElementById('todayVisits').textContent = this.stats.todayVisits;
    }

    initChart() {
        const canvas = document.getElementById('threatChart');
        if (!canvas || typeof Chart === 'undefined') {
            console.warn('Chart.js not available — skipping chart init');
            return;
        }

        const ctx = canvas.getContext('2d');
        if (!ctx) return;

        this.threatChart = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: ['Safe Sites', 'Suspicious Sites', 'Phishing Sites'],
                datasets: [{
                    data: [70, 20, 10],
                    backgroundColor: [
                        '#10b981',
                        '#f59e0b',
                        '#ef4444'
                    ],
                    borderWidth: 0
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
                    }
                }
            }
        });
        
        this.updateChart();
    }

    async updateChart() {
        if (!this.threatChart) return;

        try {
            const result = await chrome.storage.local.get(['siteHistory']);
            const siteHistory = result.siteHistory || [];
            
            const today = new Date().toDateString();
            const todaySites = siteHistory.filter(site => 
                new Date(site.timestamp).toDateString() === today
            );
            
            const safeCount = todaySites.filter(site => site.threatLevel === 'safe').length;
            const suspiciousCount = todaySites.filter(site => site.threatLevel === 'medium').length;
            const phishingCount = todaySites.filter(site => site.threatLevel === 'high').length;
            
            this.threatChart.data.datasets[0].data = [safeCount, suspiciousCount, phishingCount];
            this.threatChart.update();
        } catch (error) {
            console.error('Error updating chart:', error);
        }
    }

    setupEventListeners() {
        document.getElementById('reportBtn').addEventListener('click', () => {
            this.reportCurrentSite();
        });
        
        document.getElementById('dashboardBtn').addEventListener('click', () => {
            this.openDashboard();
        });
        
        document.getElementById('settingsBtn').addEventListener('click', () => {
            this.openSettings();
        });
    }

    async reportCurrentSite() {
        if (!this.currentTab) return;
        
        const url = this.currentTab.url;
        const domain = this.extractDomain(url);
        
        // Add to reported sites
        try {
            const result = await chrome.storage.local.get(['reportedSites']);
            const reportedSites = result.reportedSites || [];
            
            if (!reportedSites.includes(domain)) {
                reportedSites.push(domain);
                await chrome.storage.local.set({ reportedSites });
                
                this.showNotification('success', 'Site reported successfully!');
                
                // Update stats
                this.stats.threatsBlocked++;
                await this.saveStats();
                this.updateStatsDisplay();
            } else {
                this.showNotification('warning', 'Site already reported');
            }
        } catch (error) {
            console.error('Error reporting site:', error);
            this.showNotification('danger', 'Error reporting site');
        }
    }

    openDashboard() {
        chrome.tabs.create({ url: chrome.runtime.getURL('dashboard.html') });
    }

    openSettings() {
        chrome.tabs.create({ url: chrome.runtime.getURL('settings.html') });
    }

    showNotification(type, message) {
        const notification = document.createElement('div');
        notification.className = `notification ${type}`;
        notification.textContent = message;
        
        document.body.appendChild(notification);
        
        setTimeout(() => {
            notification.classList.add('show');
        }, 100);
        
        setTimeout(() => {
            notification.classList.remove('show');
            setTimeout(() => {
                document.body.removeChild(notification);
            }, 300);
        }, 3000);
    }

    updateUI() {
        this.updateStatsDisplay();
        this.updateChart();
    }
}

// Initialize the popup when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    new SafeClickPopup();
});
