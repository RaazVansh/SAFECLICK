// Phish Shield - Settings Script
class SafeClickSettings {
    constructor() {
        this.settings = {
            aiDetection: true,
            autoBlock: true,
            notifications: true,
            detectionLevel: 'medium',
            autoReport: false,
            dailyReports: true,
            localStorage: true,
            communityProtection: true
        };
        this.init();
    }

    async init() {
        await this.loadSettings();
        this.setupEventListeners();
        this.updateUI();
    }

    async loadSettings() {
        try {
            const result = await chrome.storage.local.get(['settings']);
            if (result.settings) {
                this.settings = { ...this.settings, ...result.settings };
            }
        } catch (error) {
            console.error('Error loading settings:', error);
        }
    }

    async saveSettings() {
        try {
            await chrome.storage.local.set({ settings: this.settings });
            this.showNotification('Settings saved successfully!', 'success');
        } catch (error) {
            console.error('Error saving settings:', error);
            this.showNotification('Error saving settings', 'error');
        }
    }

    setupEventListeners() {
        // Protection settings
        document.getElementById('aiDetection').addEventListener('change', (e) => {
            this.settings.aiDetection = e.target.checked;
        });

        document.getElementById('autoBlock').addEventListener('change', (e) => {
            this.settings.autoBlock = e.target.checked;
        });

        document.getElementById('notifications').addEventListener('change', (e) => {
            this.settings.notifications = e.target.checked;
        });

        // Detection level
        document.getElementById('detectionLevel').addEventListener('change', (e) => {
            this.settings.detectionLevel = e.target.value;
        });

        // Reporting settings
        document.getElementById('autoReport').addEventListener('change', (e) => {
            this.settings.autoReport = e.target.checked;
        });

        document.getElementById('dailyReports').addEventListener('change', (e) => {
            this.settings.dailyReports = e.target.checked;
        });

        // Privacy settings
        document.getElementById('communityProtection').addEventListener('change', (e) => {
            this.settings.communityProtection = e.target.checked;
        });

        // Save button
        document.querySelector('.btn-primary').addEventListener('click', () => {
            this.saveSettings();
        });

        // Reset button
        document.querySelector('.btn-outline').addEventListener('click', () => {
            this.resetSettings();
        });
    }

    updateUI() {
        // Update checkboxes
        document.getElementById('aiDetection').checked = this.settings.aiDetection;
        document.getElementById('autoBlock').checked = this.settings.autoBlock;
        document.getElementById('notifications').checked = this.settings.notifications;
        document.getElementById('autoReport').checked = this.settings.autoReport;
        document.getElementById('dailyReports').checked = this.settings.dailyReports;
        document.getElementById('communityProtection').checked = this.settings.communityProtection;

        // Update select
        document.getElementById('detectionLevel').value = this.settings.detectionLevel;
    }

    async resetSettings() {
        if (confirm('Are you sure you want to reset all settings to default values?')) {
            this.settings = {
                aiDetection: true,
                autoBlock: true,
                notifications: true,
                detectionLevel: 'medium',
                autoReport: false,
                dailyReports: true,
                localStorage: true,
                communityProtection: true
            };

            await this.saveSettings();
            this.updateUI();
            this.showNotification('Settings reset to default values', 'info');
        }
    }

    async clearSiteHistory() {
        if (confirm('Are you sure you want to clear all site history? This action cannot be undone.')) {
            try {
                await chrome.storage.local.remove(['siteHistory', 'stats']);
                this.showNotification('Site history cleared successfully', 'success');
            } catch (error) {
                console.error('Error clearing site history:', error);
                this.showNotification('Error clearing site history', 'error');
            }
        }
    }

    async exportData() {
        try {
            const result = await chrome.storage.local.get(['siteHistory', 'stats', 'reportedSites']);
            
            const exportData = {
                siteHistory: result.siteHistory || [],
                stats: result.stats || {},
                reportedSites: result.reportedSites || [],
                exportDate: new Date().toISOString(),
                version: '1.0.0'
            };

            const blob = new Blob([JSON.stringify(exportData, null, 2)], { 
                type: 'application/json' 
            });
            
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `phish-shield-data-${new Date().toISOString().split('T')[0]}.json`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);

            this.showNotification('Data exported successfully!', 'success');
        } catch (error) {
            console.error('Error exporting data:', error);
            this.showNotification('Error exporting data', 'error');
        }
    }

    showNotification(message, type = 'info') {
        const notification = document.getElementById('notification');
        const messageElement = document.getElementById('notificationMessage');
        
        messageElement.textContent = message;
        notification.className = `notification ${type}`;
        notification.classList.add('show');
        
        setTimeout(() => {
            notification.classList.remove('show');
        }, 3000);
    }

    // Get settings for other parts of the extension
    getSettings() {
        return this.settings;
    }

    // Check if a specific setting is enabled
    isEnabled(setting) {
        return this.settings[setting] === true;
    }

    // Get detection level
    getDetectionLevel() {
        return this.settings.detectionLevel;
    }
}

// Global functions for HTML onclick handlers
let settings;

document.addEventListener('DOMContentLoaded', () => {
    settings = new SafeClickSettings();
});

function saveSettings() {
    if (settings) {
        settings.saveSettings();
    }
}

function resetSettings() {
    if (settings) {
        settings.resetSettings();
    }
}

function clearSiteHistory() {
    if (settings) {
        settings.clearSiteHistory();
    }
}

function exportData() {
    if (settings) {
        settings.exportData();
    }
}

// Export settings instance for use in other scripts
if (typeof module !== 'undefined' && module.exports) {
    module.exports = SafeClickSettings;
}
