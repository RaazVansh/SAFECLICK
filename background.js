// Phish Shield - Background Service Worker
importScripts('lib/neural-network.js', 'scripts/ml-model.js');

class SafeClickBackground {
    constructor() {
        this.mlModel = new SafeClickMLModel();
        this.mlReady = this.mlModel.ready;
        this.init();
    }

    init() {
        this.setupEventListeners();
        this.initializeStorage();
    }

    setupEventListeners() {
        chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
            if (changeInfo.status === 'complete' && tab.url) {
                this.analyzeTab(tab);
            }
        });

        chrome.tabs.onActivated.addListener((activeInfo) => {
            chrome.tabs.get(activeInfo.tabId, (tab) => {
                if (tab?.url) this.analyzeTab(tab);
            });
        });

        chrome.webNavigation.onCompleted.addListener((details) => {
            if (details.frameId === 0) {
                chrome.tabs.get(details.tabId, (tab) => {
                    if (tab?.url) this.analyzeTab(tab);
                });
            }
        });

        chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
            this.handleMessage(request, sender, sendResponse);
            return true;
        });
    }

    async initializeStorage() {
        try {
            const result = await chrome.storage.local.get(['stats', 'reportedSites', 'settings']);

            if (!result.stats) {
                await chrome.storage.local.set({
                    stats: { sitesChecked: 0, threatsBlocked: 0, todayVisits: 0 }
                });
            }
            if (!result.reportedSites) {
                await chrome.storage.local.set({ reportedSites: [] });
            }
            if (!result.settings) {
                await chrome.storage.local.set({
                    settings: {
                        notifications: true,
                        autoBlock: true,
                        aiDetection: true,
                        dailyReports: true
                    }
                });
            }
        } catch (error) {
            console.error('Error initializing storage:', error);
        }
    }

    async analyzeTab(tab) {
        if (!tab.url || tab.url.startsWith('chrome://') || tab.url.startsWith('chrome-extension://')) {
            return;
        }

        try {
            const settings = await chrome.storage.local.get(['settings']);
            if (settings.settings?.aiDetection === false) return;

            const url = tab.url;
            const domain = this.extractDomain(url);

            if (await this.isSiteReported(domain)) {
                await this.blockTab(tab);
                return;
            }

            const result = await this.detectPhishing(url);
            console.log(`Phish Shield: ${url} — score ${result.threatScore.toFixed(2)} (${result.threatLevel})`);

            if (result.threatScore > 0.5) {
                await this.handleHighThreat(tab, url, result);
            } else if (result.threatScore > 0.3) {
                await this.handleMediumThreat(tab, url, result);
            } else {
                await this.recordSafeSite(url, result.threatScore);
            }

            await this.updateStats();
        } catch (error) {
            console.error('Error analyzing tab:', error);
        }
    }

    extractDomain(url) {
        try {
            return new URL(url).hostname;
        } catch {
            return 'unknown';
        }
    }

    async isSiteReported(domain) {
        try {
            const result = await chrome.storage.local.get(['reportedSites']);
            return (result.reportedSites || []).includes(domain);
        } catch {
            return false;
        }
    }

    async detectPhishing(url, contentIndicators = []) {
        await this.mlReady;
        const domain = this.extractDomain(url);
        const result = await this.mlModel.predictThreatLevel(url, domain);

        // Boost score when content script finds on-page phishing signals
        if (contentIndicators.length > 0) {
            const boost = Math.min(0.25, contentIndicators.length * 0.05);
            result.threatScore = Math.min(1, result.threatScore + boost);
            result.threatLevel = this.mlModel.mapScoreToThreatLevel(result.threatScore);
            result.contentIndicators = contentIndicators;
        }

        return result;
    }

    async handleHighThreat(tab, url, result) {
        const settings = await chrome.storage.local.get(['settings']);
        if (settings.settings?.autoBlock !== false) {
            await this.blockTab(tab);
        }
        await this.recordThreat(url, 'high', result.threatScore);
        this.showNotification('danger', 'Phishing site blocked!',
            'Phish Shield ML detected a high-risk phishing site.');
        this.updateBadge(tab.id, 'BLOCKED');
    }

    async handleMediumThreat(tab, url, result) {
        await this.recordThreat(url, 'medium', result.threatScore);
        this.showNotification('warning', 'Suspicious site detected',
            'ML analysis flagged this site. Proceed with caution.');
        this.updateBadge(tab.id, 'WARN');
    }

    async blockTab(tab) {
        try {
            const warningUrl = chrome.runtime.getURL('warning.html') +
                '?original=' + encodeURIComponent(tab.url);
            await chrome.tabs.update(tab.id, { url: warningUrl });
            await this.recordBlockedSite(tab.url);

            const result = await chrome.storage.local.get(['stats']);
            const stats = result.stats || {};
            stats.threatsBlocked = (stats.threatsBlocked || 0) + 1;
            await chrome.storage.local.set({ stats });
        } catch (error) {
            console.error('Error blocking tab:', error);
        }
    }

    async recordThreat(url, level, score) {
        await this.addToSiteHistory({
            url, domain: this.extractDomain(url),
            threatLevel: level, threatScore: score,
            timestamp: Date.now(), type: 'threat'
        });
    }

    async recordSafeSite(url, score) {
        await this.addToSiteHistory({
            url, domain: this.extractDomain(url),
            threatLevel: 'safe', threatScore: score,
            timestamp: Date.now(), type: 'safe'
        });
    }

    async recordBlockedSite(url) {
        await this.addToSiteHistory({
            url, domain: this.extractDomain(url),
            threatLevel: 'blocked', threatScore: 1.0,
            timestamp: Date.now(), type: 'blocked'
        });
    }

    async addToSiteHistory(record) {
        try {
            const result = await chrome.storage.local.get(['siteHistory']);
            const siteHistory = result.siteHistory || [];
            siteHistory.push(record);
            if (siteHistory.length > 1000) {
                siteHistory.splice(0, siteHistory.length - 1000);
            }
            await chrome.storage.local.set({ siteHistory });
        } catch (error) {
            console.error('Error saving site history:', error);
        }
    }

    async updateStats() {
        try {
            const result = await chrome.storage.local.get(['stats', 'siteHistory']);
            const stats = result.stats || { sitesChecked: 0, threatsBlocked: 0, todayVisits: 0 };
            const siteHistory = result.siteHistory || [];

            stats.sitesChecked = siteHistory.length;
            stats.threatsBlocked = siteHistory.filter(s =>
                s.threatLevel === 'high' || s.threatLevel === 'blocked'
            ).length;

            const today = new Date().toDateString();
            stats.todayVisits = siteHistory.filter(s =>
                new Date(s.timestamp).toDateString() === today
            ).length;

            await chrome.storage.local.set({ stats });
        } catch (error) {
            console.error('Error updating stats:', error);
        }
    }

    showNotification(type, title, message) {
        chrome.notifications.create({
            type: 'basic',
            iconUrl: 'icons/icon48.png',
            title, message
        });
    }

    updateBadge(tabId, text) {
        chrome.action.setBadgeText({ text, tabId });
        chrome.action.setBadgeBackgroundColor({
            color: text === 'BLOCKED' ? '#ef4444' : '#f59e0b',
            tabId
        });
    }

    async handleMessage(request, sender, sendResponse) {
        try {
            switch (request.action) {
                case 'analyzeSite': {
                    const result = await this.detectPhishing(request.url);
                    sendResponse(result);
                    break;
                }
                case 'contentAnalysis': {
                    const result = await this.detectPhishing(request.url, request.indicators || []);
                    if (result.threatScore > 0.5 && sender.tab) {
                        const tab = await chrome.tabs.get(sender.tab.id);
                        await this.handleHighThreat(tab, request.url, result);
                    }
                    sendResponse(result);
                    break;
                }
                case 'reportSite': {
                    await this.reportSite(request.domain);
                    if (this.mlModel) {
                        this.mlModel.phishingDomains.add(request.domain.toLowerCase());
                    }
                    sendResponse({ success: true });
                    break;
                }
                case 'getStats': {
                    const result = await chrome.storage.local.get(['stats']);
                    sendResponse(result.stats);
                    break;
                }
                case 'getSiteHistory': {
                    const historyResult = await chrome.storage.local.get(['siteHistory']);
                    sendResponse(historyResult.siteHistory || []);
                    break;
                }
                case 'getModelStats': {
                    await this.mlReady;
                    sendResponse(this.mlModel.getModelStats());
                    break;
                }
                case 'trainModel': {
                    await this.mlModel.updateModel();
                    sendResponse({ success: true, stats: this.mlModel.getModelStats() });
                    break;
                }
                default:
                    sendResponse({ error: 'Unknown action' });
            }
        } catch (error) {
            console.error('Message handler error:', error);
            sendResponse({ error: error.message });
        }
    }

    async reportSite(domain) {
        try {
            const result = await chrome.storage.local.get(['reportedSites']);
            const reportedSites = result.reportedSites || [];
            if (!reportedSites.includes(domain)) {
                reportedSites.push(domain);
                await chrome.storage.local.set({ reportedSites });
                const statsResult = await chrome.storage.local.get(['stats']);
                const stats = statsResult.stats || { sitesChecked: 0, threatsBlocked: 0, todayVisits: 0 };
                stats.threatsBlocked++;
                await chrome.storage.local.set({ stats });
            }
        } catch (error) {
            console.error('Error reporting site:', error);
        }
    }
}

new SafeClickBackground();
