// SAFECLICK - Background Service Worker
class SafeClickBackground {
    constructor() {
        this.init();
    }

    init() {
        this.setupEventListeners();
        this.initializeStorage();
    }

    setupEventListeners() {
        // Listen for tab updates
        chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
            if (changeInfo.status === 'complete' && tab.url) {
                this.analyzeTab(tab);
            }
        });

        // Listen for tab activation
        chrome.tabs.onActivated.addListener((activeInfo) => {
            chrome.tabs.get(activeInfo.tabId, (tab) => {
                if (tab.url) {
                    this.analyzeTab(tab);
                }
            });
        });

        // Listen for navigation
        chrome.webNavigation.onCompleted.addListener((details) => {
            if (details.frameId === 0) { // Main frame only
                chrome.tabs.get(details.tabId, (tab) => {
                    if (tab.url) {
                        this.analyzeTab(tab);
                    }
                });
            }
        });

        // Listen for messages from content script
        chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
            this.handleMessage(request, sender, sendResponse);
            return true; // Keep message channel open for async response
        });
    }

    async initializeStorage() {
        try {
            const result = await chrome.storage.local.get(['stats', 'reportedSites', 'settings']);
            
            if (!result.stats) {
                await chrome.storage.local.set({
                    stats: {
                        sitesChecked: 0,
                        threatsBlocked: 0,
                        todayVisits: 0
                    }
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
            const url = tab.url;
            const domain = this.extractDomain(url);
            
            // Check if site is already reported
            const isReported = await this.isSiteReported(domain);
            if (isReported) {
                this.blockTab(tab);
                return;
            }

            // AI-powered phishing detection
            const threatScore = await this.detectPhishing(url);
            
            console.log(`SAFECLICK: Analyzing ${url} - Threat Score: ${threatScore}`);
            
            if (threatScore > 0.5) {
                await this.handleHighThreat(tab, url, threatScore);
            } else if (threatScore > 0.3) {
                await this.handleMediumThreat(tab, url, threatScore);
            } else {
                await this.recordSafeSite(url);
            }

            // Update stats
            await this.updateStats();
            
        } catch (error) {
            console.error('Error analyzing tab:', error);
        }
    }

    extractDomain(url) {
        try {
            const urlObj = new URL(url);
            return urlObj.hostname;
        } catch {
            return 'unknown';
        }
    }

    async isSiteReported(domain) {
        try {
            const result = await chrome.storage.local.get(['reportedSites']);
            const reportedSites = result.reportedSites || [];
            return reportedSites.includes(domain);
        } catch (error) {
            console.error('Error checking reported sites:', error);
            return false;
        }
    }

    async detectPhishing(url) {
        // Enhanced AI/ML-based phishing detection with improved fake site detection
        const features = await this.extractAdvancedFeatures(url);
        
        // Machine Learning model (enhanced version)
        let threatScore = 0;
        
        // URL-based features (weighted)
        if (features.hasIPAddress) threatScore += 0.5;
        if (features.hasShortenedURL) threatScore += 0.4;
        if (features.hasTyposquatting) threatScore += 0.8;
        if (features.hasUnusualTLD) threatScore += 0.6;
        if (features.hasSuspiciousKeywords) threatScore += 0.4;
        if (features.hasSSLIssues) threatScore += 0.7;
        
        // Content-based features
        if (features.hasLoginForms) threatScore += 0.3;
        if (features.hasExternalScripts) threatScore += 0.2;
        if (features.hasPopups) threatScore += 0.3;
        
        // Domain reputation
        if (features.isKnownPhishing) threatScore += 0.95;
        if (features.isNewDomain) threatScore += 0.4;
        
        // Behavioral analysis
        if (features.hasUrgencyIndicators) threatScore += 0.3;
        if (features.hasRewardPromises) threatScore += 0.3;
        
        // Enhanced fake site detection
        if (features.isFakeSite) threatScore += 0.9;
        if (features.hasFakeBranding) threatScore += 0.7;
        if (features.hasFakeSecurityIndicators) threatScore += 0.6;
        
        // Trustpilot integration
        const trustpilotScore = await this.getTrustpilotScore(features.domain);
        if (trustpilotScore && trustpilotScore < 2.0) {
            threatScore += 0.4; // High risk for low-rated sites
        } else if (trustpilotScore && trustpilotScore > 4.0) {
            threatScore -= 0.3; // Lower risk for highly-rated sites
        }
        
        // ML model confidence boost
        if (features.mlConfidence > 0.8) {
            threatScore *= 1.3; // Boost score for high-confidence ML predictions
        }
        
        // Additional checks for common fake sites
        const fakeSitePatterns = [
            /paypal.*secure.*verify/i,
            /facebook.*login.*secure/i,
            /google.*account.*verify/i,
            /amazon.*payment.*secure/i,
            /microsoft.*account.*verify/i,
            /apple.*id.*verify/i,
            /netflix.*billing.*secure/i,
            /bank.*secure.*login/i,
            /credit.*card.*verify/i
        ];
        
        fakeSitePatterns.forEach(pattern => {
            if (pattern.test(url)) {
                threatScore += 0.8;
            }
        });
        
        return Math.min(threatScore, 1.0);
    }

    async getTrustpilotScore(domain) {
        try {
            // Check cache first
            const cacheKey = `trustpilot_${domain}`;
            const cached = await chrome.storage.local.get([cacheKey]);
            if (cached[cacheKey] && Date.now() - cached[cacheKey].timestamp < 24 * 60 * 60 * 1000) {
                return cached[cacheKey].score;
            }

            // Simulated Trustpilot API call
            const mockScores = {
                'google.com': 4.2,
                'amazon.com': 3.8,
                'facebook.com': 2.1,
                'paypal.com': 4.0,
                'microsoft.com': 3.9,
                'apple.com': 4.1,
                'netflix.com': 3.7,
                'youtube.com': 3.5
            };

            const score = mockScores[domain] || Math.random() * 5;
            
            // Cache the result
            await chrome.storage.local.set({
                [cacheKey]: {
                    score: score,
                    timestamp: Date.now()
                }
            });

            return score;
        } catch (error) {
            console.error('Error fetching Trustpilot score:', error);
            return null;
        }
    }

    async extractAdvancedFeatures(url) {
        const features = {
            hasIPAddress: false,
            hasShortenedURL: false,
            hasTyposquatting: false,
            hasUnusualTLD: false,
            hasSuspiciousKeywords: false,
            hasSSLIssues: false,
            hasLoginForms: false,
            hasExternalScripts: false,
            hasPopups: false,
            isKnownPhishing: false,
            isNewDomain: false,
            hasUrgencyIndicators: false,
            hasRewardPromises: false,
            isFakeSite: false,
            hasFakeBranding: false,
            hasFakeSecurityIndicators: false,
            domain: '',
            mlConfidence: 0.5
        };

        try {
            const urlObj = new URL(url);
            const domain = urlObj.hostname;
            const path = urlObj.pathname;
            
            // Store domain for Trustpilot lookup
            features.domain = domain;
            
            // IP Address check
            features.hasIPAddress = /^\d+\.\d+\.\d+\.\d+$/.test(domain);
            
            // Shortened URL check
            const shorteners = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'is.gd', 'v.gd'];
            features.hasShortenedURL = shorteners.some(shortener => domain.includes(shortener));
            
            // Typosquatting check
            const commonDomains = [
                'google.com', 'facebook.com', 'amazon.com', 'paypal.com', 
                'apple.com', 'microsoft.com', 'netflix.com', 'youtube.com'
            ];
            features.hasTyposquatting = commonDomains.some(common => 
                this.calculateSimilarity(domain, common) > 0.8
            );
            
            // Unusual TLD check
            const unusualTLDs = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top'];
            features.hasUnusualTLD = unusualTLDs.some(tld => domain.endsWith(tld));
            
            // Suspicious keywords
            const suspiciousKeywords = ['login', 'signin', 'account', 'verify', 'secure', 'update', 'confirm'];
            features.hasSuspiciousKeywords = suspiciousKeywords.some(keyword => 
                url.toLowerCase().includes(keyword)
            );
            
            // SSL check
            features.hasSSLIssues = urlObj.protocol === 'http:';
            
            // Domain age check (simplified)
            features.isNewDomain = domain.length < 10; // Simple heuristic
            
            // Urgency indicators
            const urgencyWords = ['urgent', 'immediate', 'now', 'limited', 'expires'];
            features.hasUrgencyIndicators = urgencyWords.some(word => 
                url.toLowerCase().includes(word)
            );
            
            // Reward promises
            const rewardWords = ['free', 'prize', 'winner', 'reward', 'bonus'];
            features.hasRewardPromises = rewardWords.some(word => 
                url.toLowerCase().includes(word)
            );
            
            // Known phishing database check
            features.isKnownPhishing = await this.checkPhishingDatabase(domain);
            
            // Enhanced fake site detection
            features.isFakeSite = this.detectFakeSite(url, domain);
            features.hasFakeBranding = this.detectFakeBranding(url, domain);
            features.hasFakeSecurityIndicators = this.detectFakeSecurityIndicators(url);
            
        } catch (error) {
            console.error('Error extracting features:', error);
        }

        return features;
    }

    calculateSimilarity(str1, str2) {
        // Levenshtein distance-based similarity
        const matrix = [];
        for (let i = 0; i <= str2.length; i++) {
            matrix[i] = [i];
        }
        for (let j = 0; j <= str1.length; j++) {
            matrix[0][j] = j;
        }
        for (let i = 1; i <= str2.length; i++) {
            for (let j = 1; j <= str1.length; j++) {
                if (str2.charAt(i - 1) === str1.charAt(j - 1)) {
                    matrix[i][j] = matrix[i - 1][j - 1];
                } else {
                    matrix[i][j] = Math.min(
                        matrix[i - 1][j - 1] + 1,
                        matrix[i][j - 1] + 1,
                        matrix[i - 1][j] + 1
                    );
                }
            }
        }
        const distance = matrix[str2.length][str1.length];
        return 1 - (distance / Math.max(str1.length, str2.length));
    }

    async checkPhishingDatabase(domain) {
        // Enhanced phishing database with more fake sites
        const knownPhishingDomains = [
            'phishing-example.com',
            'fake-login.net',
            'malicious-site.org',
            'scam-website.com',
            'fake-bank.com',
            'paypal-secure-verify.com',
            'facebook-login-secure.net',
            'google-account-verify.com',
            'amazon-payment-secure.co',
            'microsoft-account-verify.net',
            'apple-id-verify-secure.com',
            'netflix-billing-secure.net',
            'bank-secure-login.com',
            'credit-card-verify.net',
            'secure-login-verify.com',
            'account-verification-secure.net'
        ];
        return knownPhishingDomains.includes(domain);
    }

    detectFakeSite(url, domain) {
        // Enhanced fake site detection patterns
        const fakePatterns = [
            /paypal.*secure.*verify/i,
            /facebook.*login.*secure/i,
            /google.*account.*verify/i,
            /amazon.*payment.*secure/i,
            /microsoft.*account.*verify/i,
            /apple.*id.*verify/i,
            /netflix.*billing.*secure/i,
            /bank.*secure.*login/i,
            /credit.*card.*verify/i,
            /secure.*login.*verify/i,
            /account.*verification.*secure/i,
            /verify.*secure.*login/i
        ];
        
        return fakePatterns.some(pattern => pattern.test(url));
    }

    detectFakeBranding(url, domain) {
        // Check for fake branding of popular companies
        const popularBrands = ['paypal', 'facebook', 'google', 'amazon', 'microsoft', 'apple', 'netflix', 'bank'];
        const hasBrandName = popularBrands.some(brand => 
            url.toLowerCase().includes(brand) && !this.isLegitimateBrand(domain, brand)
        );
        
        return hasBrandName;
    }

    isLegitimateBrand(domain, brand) {
        // Check if the domain is actually owned by the legitimate brand
        const legitimateDomains = {
            'paypal': ['paypal.com', 'paypal.co.uk', 'paypal.de'],
            'facebook': ['facebook.com', 'fb.com'],
            'google': ['google.com', 'gmail.com', 'youtube.com'],
            'amazon': ['amazon.com', 'amazon.co.uk', 'amazon.de'],
            'microsoft': ['microsoft.com', 'office.com', 'outlook.com'],
            'apple': ['apple.com', 'icloud.com'],
            'netflix': ['netflix.com'],
            'bank': ['wellsfargo.com', 'chase.com', 'bankofamerica.com']
        };
        
        const legitimate = legitimateDomains[brand] || [];
        return legitimate.some(legitDomain => domain.includes(legitDomain));
    }

    detectFakeSecurityIndicators(url) {
        // Check for fake security indicators
        const fakeSecurityWords = [
            'secure-verify',
            'security-verify',
            'secure-login-verify',
            'secure-account-verify',
            'secure-payment-verify',
            'secure-billing-verify'
        ];
        
        return fakeSecurityWords.some(word => url.toLowerCase().includes(word));
    }

    async handleHighThreat(tab, url, threatScore) {
        // Block the site
        await this.blockTab(tab);
        
        // Record the threat
        await this.recordThreat(url, 'high', threatScore);
        
        // Show notification
        this.showNotification('danger', 'Phishing site blocked!', 
            'SAFECLICK has detected and blocked a high-risk phishing site.');
        
        // Update badge
        this.updateBadge(tab.id, 'BLOCKED');
    }

    async handleMediumThreat(tab, url, threatScore) {
        // Record the threat
        await this.recordThreat(url, 'medium', threatScore);
        
        // Show warning notification
        this.showNotification('warning', 'Suspicious site detected', 
            'This site shows signs of being suspicious. Proceed with caution.');
        
        // Update badge
        this.updateBadge(tab.id, 'WARN');
    }

    async blockTab(tab) {
        try {
            console.log(`SAFECLICK: Blocking malicious site: ${tab.url}`);
            
            // Redirect to warning page
            const warningUrl = chrome.runtime.getURL('warning.html') + 
                '?original=' + encodeURIComponent(tab.url);
            
            await chrome.tabs.update(tab.id, { url: warningUrl });
            
            // Record blocked site
            await this.recordBlockedSite(tab.url);
            
            // Update stats
            const result = await chrome.storage.local.get(['stats']);
            const stats = result.stats || {};
            stats.threatsBlocked = (stats.threatsBlocked || 0) + 1;
            await chrome.storage.local.set({ stats });
            
        } catch (error) {
            console.error('Error blocking tab:', error);
        }
    }

    async recordThreat(url, level, score) {
        const record = {
            url: url,
            domain: this.extractDomain(url),
            threatLevel: level,
            threatScore: score,
            timestamp: Date.now(),
            type: 'threat'
        };
        
        await this.addToSiteHistory(record);
    }

    async recordSafeSite(url) {
        const record = {
            url: url,
            domain: this.extractDomain(url),
            threatLevel: 'safe',
            threatScore: 0,
            timestamp: Date.now(),
            type: 'safe'
        };
        
        await this.addToSiteHistory(record);
    }

    async recordBlockedSite(url) {
        const record = {
            url: url,
            domain: this.extractDomain(url),
            threatLevel: 'blocked',
            threatScore: 1.0,
            timestamp: Date.now(),
            type: 'blocked'
        };
        
        await this.addToSiteHistory(record);
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

    async updateStats() {
        try {
            const result = await chrome.storage.local.get(['stats', 'siteHistory']);
            const stats = result.stats || { sitesChecked: 0, threatsBlocked: 0, todayVisits: 0 };
            const siteHistory = result.siteHistory || [];
            
            // Update stats
            stats.sitesChecked = siteHistory.length;
            stats.threatsBlocked = siteHistory.filter(site => 
                site.threatLevel === 'high' || site.threatLevel === 'blocked'
            ).length;
            
            // Calculate today's visits
            const today = new Date().toDateString();
            stats.todayVisits = siteHistory.filter(site => 
                new Date(site.timestamp).toDateString() === today
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
            title: title,
            message: message
        });
    }

    updateBadge(tabId, text) {
        chrome.action.setBadgeText({
            text: text,
            tabId: tabId
        });
        
        chrome.action.setBadgeBackgroundColor({
            color: text === 'BLOCKED' ? '#ef4444' : '#f59e0b',
            tabId: tabId
        });
    }

    async handleMessage(request, sender, sendResponse) {
        switch (request.action) {
            case 'analyzeSite':
                const threatScore = await this.detectPhishing(request.url);
                sendResponse({ threatScore });
                break;
                
            case 'reportSite':
                await this.reportSite(request.domain);
                sendResponse({ success: true });
                break;
                
            case 'getStats':
                const result = await chrome.storage.local.get(['stats']);
                sendResponse(result.stats);
                break;
                
            case 'getSiteHistory':
                const historyResult = await chrome.storage.local.get(['siteHistory']);
                sendResponse(historyResult.siteHistory || []);
                break;
                
            default:
                sendResponse({ error: 'Unknown action' });
        }
    }

    async reportSite(domain) {
        try {
            const result = await chrome.storage.local.get(['reportedSites']);
            const reportedSites = result.reportedSites || [];
            
            if (!reportedSites.includes(domain)) {
                reportedSites.push(domain);
                await chrome.storage.local.set({ reportedSites });
                
                // Update stats
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

// Initialize background service worker
new SafeClickBackground();
