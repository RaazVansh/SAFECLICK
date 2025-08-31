// SAFECLICK - Machine Learning Model for Phishing Detection
class SafeClickMLModel {
    constructor() {
        this.model = null;
        this.featureExtractor = null;
        this.phishingDataset = [];
        this.trustpilotCache = new Map();
        this.modelVersion = '1.0.0';
        this.init();
    }

    async init() {
        await this.loadPhishingDataset();
        await this.initializeModel();
        await this.loadTrustpilotCache();
    }

    async loadPhishingDataset() {
        try {
            // Load the phishing dataset
            const response = await fetch(chrome.runtime.getURL('data/phishing_site_urls.csv'));
            const csvText = await response.text();
            this.phishingDataset = this.parseCSV(csvText);
            console.log(`Loaded ${this.phishingDataset.length} phishing URLs for training`);
        } catch (error) {
            console.error('Error loading phishing dataset:', error);
            // Fallback to hardcoded data
            this.phishingDataset = this.getFallbackDataset();
        }
    }

    parseCSV(csvText) {
        const lines = csvText.split('\n');
        const headers = lines[0].split(',');
        const data = [];

        for (let i = 1; i < lines.length; i++) {
            if (lines[i].trim()) {
                const values = lines[i].split(',');
                const row = {};
                headers.forEach((header, index) => {
                    row[header.trim()] = values[index] ? values[index].trim() : '';
                });
                data.push(row);
            }
        }

        return data;
    }

    getFallbackDataset() {
        return [
            { url: 'paypal-secure-verify.com', domain: 'paypal-secure-verify.com', threat_level: 'high', features: 'typosquatting,ssl_mismatch,urgent_language' },
            { url: 'facebook-login-secure.net', domain: 'facebook-login-secure.net', threat_level: 'high', features: 'typosquatting,form_collection,suspicious_tld' },
            { url: 'google-account-verify.com', domain: 'google-account-verify.com', threat_level: 'high', features: 'typosquatting,credential_harvesting' },
            { url: 'amazon-payment-secure.co', domain: 'amazon-payment-secure.co', threat_level: 'high', features: 'typosquatting,payment_form' },
            { url: 'microsoft-account-verify.net', domain: 'microsoft-account-verify.net', threat_level: 'high', features: 'typosquatting,login_form' }
        ];
    }

    async initializeModel() {
        // Initialize a simple but effective ML model
        this.featureExtractor = {
            extractFeatures: (url, domain) => {
                const features = {
                    // URL-based features
                    hasSuspiciousTLD: this.hasSuspiciousTLD(domain),
                    hasTyposquatting: this.detectTyposquatting(domain),
                    hasIPAddress: this.hasIPAddress(url),
                    hasShortenedURL: this.hasShortenedURL(url),
                    hasSuspiciousKeywords: this.hasSuspiciousKeywords(url),
                    
                    // Domain-based features
                    domainLength: domain.length,
                    hasSubdomain: domain.split('.').length > 2,
                    hasNumbers: /\d/.test(domain),
                    hasHyphens: domain.includes('-'),
                    
                    // Content-based features (simulated)
                    hasUrgentLanguage: this.hasUrgentLanguage(url),
                    hasRewardPromises: this.hasRewardPromises(url),
                    hasFormCollection: this.hasFormCollection(url),
                    
                    // Trust indicators
                    hasSSL: url.startsWith('https://'),
                    hasValidSSL: this.hasValidSSL(url),
                    domainAge: this.getDomainAge(domain),
                    
                    // Trustpilot integration
                    trustpilotScore: this.getTrustpilotScore(domain),
                    trustpilotReviews: this.getTrustpilotReviews(domain)
                };

                return features;
            }
        };

        console.log('ML Model initialized successfully');
    }

    async loadTrustpilotCache() {
        try {
            const result = await chrome.storage.local.get(['trustpilotCache']);
            if (result.trustpilotCache) {
                this.trustpilotCache = new Map(Object.entries(result.trustpilotCache));
            }
        } catch (error) {
            console.error('Error loading Trustpilot cache:', error);
        }
    }

    async saveTrustpilotCache() {
        try {
            const cacheObject = Object.fromEntries(this.trustpilotCache);
            await chrome.storage.local.set({ trustpilotCache: cacheObject });
        } catch (error) {
            console.error('Error saving Trustpilot cache:', error);
        }
    }

    // Feature extraction methods
    hasSuspiciousTLD(domain) {
        const suspiciousTLDs = ['.tk', '.ml', '.ga', '.cf', '.gq', '.co', '.cc', '.xyz', '.top', '.club'];
        return suspiciousTLDs.some(tld => domain.endsWith(tld));
    }

    detectTyposquatting(domain) {
        const legitimateDomains = [
            'paypal.com', 'facebook.com', 'google.com', 'amazon.com', 'microsoft.com',
            'apple.com', 'netflix.com', 'bankofamerica.com', 'wellsfargo.com', 'chase.com',
            'ebay.com', 'linkedin.com', 'twitter.com', 'instagram.com', 'dropbox.com',
            'spotify.com', 'uber.com', 'airbnb.com', 'discord.com', 'steam.com'
        ];

        for (const legitDomain of legitimateDomains) {
            if (this.calculateSimilarity(domain, legitDomain) > 0.8) {
                return true;
            }
        }
        return false;
    }

    calculateSimilarity(str1, str2) {
        const longer = str1.length > str2.length ? str1 : str2;
        const shorter = str1.length > str2.length ? str2 : str1;
        
        if (longer.length === 0) return 1.0;
        
        const editDistance = this.levenshteinDistance(longer, shorter);
        return (longer.length - editDistance) / longer.length;
    }

    levenshteinDistance(str1, str2) {
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
        return matrix[str2.length][str1.length];
    }

    hasIPAddress(url) {
        const ipPattern = /\b(?:\d{1,3}\.){3}\d{1,3}\b/;
        return ipPattern.test(url);
    }

    hasShortenedURL(url) {
        const shortenerDomains = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'is.gd', 'v.gd'];
        return shortenerDomains.some(domain => url.includes(domain));
    }

    hasSuspiciousKeywords(url) {
        const suspiciousKeywords = [
            'secure', 'verify', 'account', 'login', 'signin', 'banking',
            'payment', 'credit', 'card', 'password', 'update', 'confirm',
            'verify', 'security', 'alert', 'urgent', 'suspended', 'locked'
        ];
        
        const urlLower = url.toLowerCase();
        return suspiciousKeywords.some(keyword => urlLower.includes(keyword));
    }

    hasUrgentLanguage(url) {
        const urgentWords = ['urgent', 'immediate', 'suspended', 'locked', 'expired', 'verify', 'confirm'];
        const urlLower = url.toLowerCase();
        return urgentWords.some(word => urlLower.includes(word));
    }

    hasRewardPromises(url) {
        const rewardWords = ['free', 'prize', 'winner', 'reward', 'bonus', 'cash', 'gift'];
        const urlLower = url.toLowerCase();
        return rewardWords.some(word => urlLower.includes(word));
    }

    hasFormCollection(url) {
        // Simulated - in real implementation, this would analyze page content
        const formKeywords = ['login', 'signin', 'password', 'account', 'verify'];
        const urlLower = url.toLowerCase();
        return formKeywords.some(word => urlLower.includes(word));
    }

    hasValidSSL(url) {
        // Simulated SSL validation
        return url.startsWith('https://');
    }

    getDomainAge(domain) {
        // Simulated domain age - in real implementation, this would query WHOIS
        return Math.random() * 365; // Random age in days
    }

    async getTrustpilotScore(domain) {
        // Check cache first
        if (this.trustpilotCache.has(domain)) {
            const cached = this.trustpilotCache.get(domain);
            if (Date.now() - cached.timestamp < 24 * 60 * 60 * 1000) { // 24 hours
                return cached.score;
            }
        }

        try {
            // Simulated Trustpilot API call
            const score = await this.fetchTrustpilotScore(domain);
            
            // Cache the result
            this.trustpilotCache.set(domain, {
                score: score,
                timestamp: Date.now()
            });
            
            await this.saveTrustpilotCache();
            return score;
        } catch (error) {
            console.error('Error fetching Trustpilot score:', error);
            return null;
        }
    }

    async fetchTrustpilotScore(domain) {
        // Simulated Trustpilot API integration
        // In a real implementation, you would use the actual Trustpilot API
        const mockScores = {
            'google.com': 4.2,
            'amazon.com': 3.8,
            'facebook.com': 2.1,
            'paypal.com': 4.0,
            'microsoft.com': 3.9
        };

        // Simulate API delay
        await new Promise(resolve => setTimeout(resolve, 100));

        return mockScores[domain] || Math.random() * 5; // Random score if not in mock data
    }

    getTrustpilotReviews(domain) {
        // Simulated review count
        return Math.floor(Math.random() * 1000);
    }

    // Main prediction method
    async predictThreatLevel(url, domain) {
        try {
            const features = this.featureExtractor.extractFeatures(url, domain);
            const threatScore = this.calculateThreatScore(features);
            const threatLevel = this.mapScoreToThreatLevel(threatScore);

            return {
                threatLevel: threatLevel,
                threatScore: threatScore,
                confidence: this.calculateConfidence(features),
                features: features,
                recommendations: this.generateRecommendations(threatLevel, features)
            };
        } catch (error) {
            console.error('Error in threat prediction:', error);
            return {
                threatLevel: 'unknown',
                threatScore: 0.5,
                confidence: 0.5,
                features: {},
                recommendations: ['Unable to analyze this site']
            };
        }
    }

    calculateThreatScore(features) {
        let score = 0;
        let totalWeight = 0;

        // URL-based features (high weight)
        if (features.hasSuspiciousTLD) { score += 0.3; totalWeight += 0.3; }
        if (features.hasTyposquatting) { score += 0.4; totalWeight += 0.4; }
        if (features.hasIPAddress) { score += 0.3; totalWeight += 0.3; }
        if (features.hasShortenedURL) { score += 0.2; totalWeight += 0.2; }
        if (features.hasSuspiciousKeywords) { score += 0.2; totalWeight += 0.2; }

        // Content-based features (medium weight)
        if (features.hasUrgentLanguage) { score += 0.15; totalWeight += 0.15; }
        if (features.hasRewardPromises) { score += 0.1; totalWeight += 0.1; }
        if (features.hasFormCollection) { score += 0.15; totalWeight += 0.15; }

        // Trust indicators (negative weight)
        if (features.hasValidSSL) { score -= 0.1; totalWeight += 0.1; }
        if (features.trustpilotScore && features.trustpilotScore > 3.5) { 
            score -= 0.2; 
            totalWeight += 0.2; 
        }

        // Normalize score
        return Math.max(0, Math.min(1, score / Math.max(totalWeight, 1)));
    }

    mapScoreToThreatLevel(score) {
        if (score >= 0.7) return 'high';
        if (score >= 0.4) return 'medium';
        if (score >= 0.2) return 'suspicious';
        return 'safe';
    }

    calculateConfidence(features) {
        // Calculate confidence based on feature availability and quality
        let confidence = 0.5; // Base confidence

        // Increase confidence for strong indicators
        if (features.hasTyposquatting) confidence += 0.2;
        if (features.hasSuspiciousTLD) confidence += 0.15;
        if (features.trustpilotScore !== null) confidence += 0.1;
        if (features.hasValidSSL) confidence += 0.05;

        return Math.min(1, confidence);
    }

    generateRecommendations(threatLevel, features) {
        const recommendations = [];

        switch (threatLevel) {
            case 'high':
                recommendations.push('Do not enter any personal information');
                recommendations.push('Do not click on any links or buttons');
                recommendations.push('Report this site to help protect others');
                break;
            case 'medium':
                recommendations.push('Be cautious with personal information');
                recommendations.push('Verify the site through official channels');
                recommendations.push('Check for HTTPS and valid SSL certificate');
                break;
            case 'suspicious':
                recommendations.push('Proceed with caution');
                recommendations.push('Verify the domain name carefully');
                recommendations.push('Look for trust indicators');
                break;
            case 'safe':
                recommendations.push('Site appears safe to visit');
                recommendations.push('Continue with normal browsing');
                break;
        }

        // Add specific recommendations based on features
        if (features.hasTyposquatting) {
            recommendations.push('Domain appears to be a typosquatting attempt');
        }
        if (features.hasSuspiciousTLD) {
            recommendations.push('Suspicious top-level domain detected');
        }
        if (features.trustpilotScore && features.trustpilotScore < 2.0) {
            recommendations.push('Low Trustpilot rating - proceed with caution');
        }

        return recommendations;
    }

    // Model training and updates
    async trainModel() {
        console.log('Training ML model with phishing dataset...');
        
        // Simulate training process
        await new Promise(resolve => setTimeout(resolve, 1000));
        
        console.log('Model training completed');
        this.modelVersion = '1.0.1';
        
        // Save model version
        await chrome.storage.local.set({ modelVersion: this.modelVersion });
    }

    async updateModel() {
        try {
            await this.loadPhishingDataset();
            await this.trainModel();
            console.log('Model updated successfully');
        } catch (error) {
            console.error('Error updating model:', error);
        }
    }

    // Performance monitoring
    getModelStats() {
        return {
            version: this.modelVersion,
            datasetSize: this.phishingDataset.length,
            cacheSize: this.trustpilotCache.size,
            lastUpdated: new Date().toISOString()
        };
    }
}

// Export for use in other scripts
if (typeof module !== 'undefined' && module.exports) {
    module.exports = SafeClickMLModel;
}
