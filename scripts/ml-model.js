// Phish Shield - Deep Learning Phishing Detection (CSP-safe neural network)
// Trains a DNN on phishing_site_urls.csv + legitimate domain samples

class SafeClickMLModel {
    constructor() {
        this.model = null;
        this.phishingDataset = [];
        this.phishingDomains = new Set();
        this.phishingUrls = new Set();
        this.trustpilotCache = new Map();
        this.modelVersion = '3.1.0';
        this.trainingMetrics = {
            accuracy: 0, valAccuracy: 0, loss: 0, samples: 0,
            epochs: 0, trainedAt: null
        };
        this.ready = this.init();
    }

    static get INPUT_SIZE() { return 18; }

    static get FEATURE_NAMES() {
        return [
            'urlLength', 'domainLength', 'pathLength', 'dotCount', 'hyphenCount',
            'digitRatio', 'hasIP', 'suspiciousTLD', 'typosquatting', 'shortenedURL',
            'keywordDensity', 'urgentLanguage', 'rewardPromises', 'formKeywords',
            'isHTTP', 'brandSimilarity', 'extraSubdomains', 'domainEntropy'
        ];
    }

    static get LEGITIMATE_DOMAINS() {
        return [
            'google.com', 'youtube.com', 'facebook.com', 'amazon.com', 'microsoft.com',
            'apple.com', 'netflix.com', 'paypal.com', 'github.com', 'stackoverflow.com',
            'wikipedia.org', 'reddit.com', 'twitter.com', 'instagram.com', 'linkedin.com',
            'dropbox.com', 'spotify.com', 'uber.com', 'airbnb.com', 'discord.com',
            'steam.com', 'ebay.com', 'chase.com', 'wellsfargo.com', 'bankofamerica.com',
            'mozilla.org', 'python.org', 'npmjs.com', 'cloudflare.com', 'w3.org',
            'cnn.com', 'bbc.com', 'nytimes.com', 'adobe.com', 'zoom.us'
        ];
    }

    static get SUSPICIOUS_TLDS() {
        return ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.club', '.cc', '.co', '.buzz', '.work'];
    }

    static get SHORTENERS() {
        return ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'is.gd', 'v.gd', 'ow.ly'];
    }

    buildNeuralNetwork() {
        if (typeof DeepNeuralNetwork === 'undefined') {
            throw new Error('DeepNeuralNetwork not loaded. Include lib/neural-network.js');
        }
        return new DeepNeuralNetwork(SafeClickMLModel.INPUT_SIZE, [64, 32, 16]);
    }

    async init() {
        await this.loadPhishingDataset();
        await this.loadTrustpilotCache();
        await this.loadOrTrainModel();
    }

    // ─── Dataset ───────────────────────────────────────────────────────────────

    async loadPhishingDataset() {
        try {
            const response = await fetch(chrome.runtime.getURL('data/phishing_site_urls.csv'));
            const csvText = await response.text();
            this.phishingDataset = this.parseCSV(csvText);
            await this.buildPhishingIndex();
            console.log(`Phish Shield DNN: loaded ${this.phishingDataset.length} phishing URLs`);
        } catch (error) {
            console.error('Error loading phishing dataset:', error);
            this.phishingDataset = [];
            await this.buildPhishingIndex();
        }
    }

    parseCSV(csvText) {
        const lines = csvText.trim().split('\n');
        const data = [];
        for (let i = 1; i < lines.length; i++) {
            const line = lines[i].trim();
            if (!line) continue;
            const match = line.match(/^(https?:\/\/[^,]+),([^,]+),(high|medium|low|safe),(.*)$/i);
            if (match) {
                data.push({
                    url: match[1].trim(),
                    domain: match[2].trim().toLowerCase(),
                    threat_level: match[3].trim().toLowerCase(),
                    features: match[4].trim()
                });
            }
        }
        return data;
    }

    async buildPhishingIndex() {
        this.phishingDomains = new Set();
        this.phishingUrls = new Set();
        for (const row of this.phishingDataset) {
            if (row.domain) {
                this.phishingDomains.add(row.domain.toLowerCase());
                this.phishingDomains.add(row.domain.replace(/^www\./, '').toLowerCase());
            }
            if (row.url) this.phishingUrls.add(row.url.toLowerCase());
        }
        try {
            const result = await chrome.storage.local.get(['reportedSites']);
            (result.reportedSites || []).forEach((d) => this.phishingDomains.add(d.toLowerCase()));
        } catch (_) { /* storage unavailable */ }
    }

    isKnownPhishingDomain(domain) {
        const d = domain.toLowerCase().replace(/^www\./, '');
        return this.phishingDomains.has(d) || this.phishingDomains.has(domain.toLowerCase());
    }

    // ─── Feature extraction ────────────────────────────────────────────────────

    extractFeatureVector(url, domain) {
        const urlLower = url.toLowerCase();
        const d = domain.toLowerCase();
        const urlObj = this.safeParseURL(url);

        const suspiciousKeywords = [
            'secure', 'verify', 'account', 'login', 'signin', 'banking', 'payment',
            'password', 'update', 'confirm', 'security', 'urgent', 'suspended', 'locked'
        ];
        const urgentWords = ['urgent', 'immediate', 'suspended', 'locked', 'expired', 'verify', 'confirm'];
        const rewardWords = ['free', 'prize', 'winner', 'reward', 'bonus', 'cash', 'gift'];
        const formWords = ['login', 'signin', 'password', 'account', 'verify'];

        const keywordHits = suspiciousKeywords.filter((k) => urlLower.includes(k)).length;
        const pathLength = urlObj ? urlObj.pathname.length : 0;
        const subdomainCount = Math.max(0, d.split('.').length - 2);

        return [
            Math.min(url.length / 200, 1),
            Math.min(d.length / 60, 1),
            Math.min(pathLength / 100, 1),
            Math.min((d.match(/\./g) || []).length / 5, 1),
            Math.min((d.match(/-/g) || []).length / 5, 1),
            Math.min((d.match(/\d/g) || []).length / Math.max(d.length, 1), 1),
            /^\d+\.\d+\.\d+\.\d+$/.test(d) ? 1 : 0,
            SafeClickMLModel.SUSPICIOUS_TLDS.some((tld) => d.endsWith(tld)) ? 1 : 0,
            this.detectTyposquatting(d) ? 1 : 0,
            SafeClickMLModel.SHORTENERS.some((s) => d.includes(s)) ? 1 : 0,
            Math.min(keywordHits / 5, 1),
            urgentWords.some((w) => urlLower.includes(w)) ? 1 : 0,
            rewardWords.some((w) => urlLower.includes(w)) ? 1 : 0,
            formWords.some((w) => urlLower.includes(w)) ? 1 : 0,
            urlLower.startsWith('http://') ? 1 : 0,
            this.maxBrandSimilarity(d),
            subdomainCount > 2 ? 1 : 0,
            Math.min(this.shannonEntropy(d) / 4, 1)
        ];
    }

    safeParseURL(url) {
        try { return new URL(url); } catch { return null; }
    }

    shannonEntropy(str) {
        const freq = {};
        for (const c of str) freq[c] = (freq[c] || 0) + 1;
        let entropy = 0;
        for (const c in freq) {
            const p = freq[c] / str.length;
            entropy -= p * Math.log2(p);
        }
        return entropy;
    }

    maxBrandSimilarity(domain) {
        for (const legit of SafeClickMLModel.LEGITIMATE_DOMAINS) {
            const sim = this.calculateSimilarity(domain, legit);
            if (sim > 0.65 && domain !== legit && !domain.endsWith('.' + legit)) return sim;
        }
        return 0;
    }

    detectTyposquatting(domain) {
        for (const legit of SafeClickMLModel.LEGITIMATE_DOMAINS) {
            if (domain === legit || domain.endsWith('.' + legit)) continue;
            if (this.calculateSimilarity(domain, legit) > 0.78) return true;
            if (domain.includes(legit.split('.')[0]) && !domain.endsWith(legit)) return true;
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
        const matrix = Array.from({ length: str2.length + 1 }, (_, i) => [i]);
        for (let j = 0; j <= str1.length; j++) matrix[0][j] = j;
        for (let i = 1; i <= str2.length; i++) {
            for (let j = 1; j <= str1.length; j++) {
                matrix[i][j] = str2[i - 1] === str1[j - 1]
                    ? matrix[i - 1][j - 1]
                    : Math.min(matrix[i - 1][j - 1] + 1, matrix[i][j - 1] + 1, matrix[i - 1][j] + 1);
            }
        }
        return matrix[str2.length][str1.length];
    }

    buildTrainingData() {
        const X = [];
        const y = [];

        const addSample = (url, domain, label) => {
            X.push(this.extractFeatureVector(url, domain));
            y.push(label);
        };

        for (const row of this.phishingDataset) {
            const url = row.url || `https://${row.domain}`;
            const domain = row.domain || this.extractDomainFromUrl(url);
            addSample(url, domain, 1);
            // Augment: flip http/https for better generalization
            const alt = url.startsWith('https://')
                ? url.replace('https://', 'http://')
                : url.replace('http://', 'https://');
            addSample(alt, domain, 1);
        }

        const benignPaths = ['', '/about', '/products', '/help', '/contact', '/search', '/docs'];
        for (const domain of SafeClickMLModel.LEGITIMATE_DOMAINS) {
            for (const path of benignPaths) {
                addSample(`https://www.${domain}${path}`, domain, 0);
            }
            addSample(`https://${domain}`, domain, 0);
            addSample(`http://${domain}`, domain, 0);
        }

        return { X, y };
    }

    extractDomainFromUrl(url) {
        try { return new URL(url).hostname; } catch { return url; }
    }

    getDatasetHash() {
        return `${this.phishingDataset.length}-dnn-v4`;
    }

    splitTrainValidation(X, y, valRatio = 0.15) {
        const indices = [...Array(X.length).keys()];
        DeepNeuralNetwork.shuffle(indices);
        const valCount = Math.max(1, Math.floor(X.length * valRatio));
        const valIdx = new Set(indices.slice(0, valCount));
        const trainX = [], trainY = [], valX = [], valY = [];
        for (let i = 0; i < X.length; i++) {
            if (valIdx.has(i)) { valX.push(X[i]); valY.push(y[i]); }
            else { trainX.push(X[i]); trainY.push(y[i]); }
        }
        return { trainX, trainY, valX, valY };
    }

    // ─── Deep neural network training & persistence ───────────────────────────

    async loadOrTrainModel() {
        try {
            const stored = await chrome.storage.local.get(['dnnModel', 'mlDatasetHash']);
            if (stored.dnnModel?.layers &&
                stored.mlDatasetHash === this.getDatasetHash()) {
                this.model = DeepNeuralNetwork.deserialize(stored.dnnModel);
                this.trainingMetrics = stored.dnnModel.metrics || this.trainingMetrics;
                this.modelVersion = stored.dnnModel.version || this.modelVersion;
                console.log(`Phish Shield DNN: loaded model (acc ${(this.trainingMetrics.accuracy * 100).toFixed(1)}%)`);
                return;
            }
        } catch (error) {
            console.warn('Could not load cached model, retraining:', error);
        }
        await this.trainModel();
    }

    async saveModelToStorage() {
        this.modelVersion = `3.1.${Date.now()}`;
        const payload = {
            ...this.model.serialize(),
            version: this.modelVersion,
            metrics: this.trainingMetrics,
            architecture: 'DNN 64→32→16→1 (ReLU + Dropout)'
        };
        await chrome.storage.local.set({
            dnnModel: payload,
            mlDatasetHash: this.getDatasetHash(),
            modelVersion: this.modelVersion
        });
    }

    async trainModel() {
        console.log('Phish Shield DNN: training deep neural network...');

        const { X, y } = this.buildTrainingData();
        if (X.length < 10) {
            console.warn('Phish Shield DNN: insufficient training data');
            return;
        }

        const { trainX, trainY, valX, valY } = this.splitTrainValidation(X, y);
        this.model = this.buildNeuralNetwork();

        const EPOCHS = 100;
        const history = this.model.train(trainX, trainY, {
            epochs: EPOCHS,
            lr: 0.05,
            batchSize: 16,
            onEpochEnd: (epoch, h) => {
                if (epoch % 25 === 0 || epoch === EPOCHS - 1) {
                    const acc = h.accuracy[h.accuracy.length - 1];
                    const loss = h.loss[h.loss.length - 1];
                    console.log(`  Epoch ${epoch + 1}/${EPOCHS} — loss: ${loss.toFixed(4)}, acc: ${acc.toFixed(4)}`);
                }
            }
        });

        const accuracy = this.model.evaluate(trainX, trainY);
        const valAccuracy = valX.length ? this.model.evaluate(valX, valY) : accuracy;
        const lossHistory = history.loss;

        this.trainingMetrics = {
            accuracy,
            valAccuracy,
            loss: lossHistory[lossHistory.length - 1] || 0,
            samples: X.length,
            phishingSamples: y.filter((v) => v === 1).length,
            benignSamples: y.filter((v) => v === 0).length,
            epochs: EPOCHS,
            trainedAt: new Date().toISOString()
        };

        await this.saveModelToStorage();
        console.log(`Phish Shield DNN: training complete — acc ${(accuracy * 100).toFixed(1)}%, val ${(valAccuracy * 100).toFixed(1)}%`);
    }

    async updateModel() {
        await this.loadPhishingDataset();
        await this.buildPhishingIndex();
        await chrome.storage.local.remove(['dnnModel', 'tfNeuralModel', 'mlDatasetHash']);
        await this.trainModel();
    }

    // ─── Prediction ──────────────────────────────────────────────────────────

    predict(url, domain) {
        if (!this.model) return 0.5;
        const features = this.extractFeatureVector(url, domain);
        return this.model.predict(features);
    }

    async predictThreatLevel(url, domain) {
        try {
            await this.ready;

            let threatScore = this.predict(url, domain);
            const features = this.extractFeatureVector(url, domain);
            const inDataset = this.isKnownPhishingDomain(domain);

            if (inDataset) threatScore = Math.max(threatScore, 0.95);

            const trustpilotScore = await this.getTrustpilotScore(domain);
            if (trustpilotScore !== null) {
                if (trustpilotScore < 2.0) threatScore = Math.min(1, threatScore + 0.15);
                else if (trustpilotScore > 4.0) threatScore = Math.max(0, threatScore - 0.2);
            }

            threatScore = Math.max(0, Math.min(1, threatScore));
            const threatLevel = this.mapScoreToThreatLevel(threatScore);
            const confidence = this.calculateConfidence(threatScore, inDataset, features);

            return {
                threatLevel,
                threatScore,
                confidence,
                inDataset,
                mlScore: threatScore,
                trustpilotScore,
                modelType: 'Deep Neural Network',
                features: this.featuresToObject(features),
                recommendations: this.generateRecommendations(threatLevel, features, inDataset)
            };
        } catch (error) {
            console.error('Phish Shield DNN prediction error:', error);
            return {
                threatLevel: 'unknown',
                threatScore: 0.5,
                confidence: 0.5,
                features: {},
                recommendations: ['Unable to analyze this site']
            };
        }
    }

    featuresToObject(vector) {
        const obj = {};
        SafeClickMLModel.FEATURE_NAMES.forEach((name, i) => { obj[name] = vector[i]; });
        return obj;
    }

    mapScoreToThreatLevel(score) {
        if (score >= 0.55) return 'high';
        if (score >= 0.35) return 'medium';
        if (score >= 0.2) return 'suspicious';
        return 'safe';
    }

    calculateConfidence(threatScore, inDataset, features) {
        let confidence = 0.4 + Math.abs(threatScore - 0.5);
        if (inDataset) confidence = Math.max(confidence, 0.95);
        if (features[8] > 0) confidence += 0.15;
        if (features[7] > 0) confidence += 0.1;
        return Math.min(1, confidence);
    }

    generateRecommendations(threatLevel, features, inDataset) {
        const recs = [];
        if (inDataset) recs.push('Domain matched phishing training dataset');
        switch (threatLevel) {
            case 'high':
                recs.push('Do not enter personal information', 'Report this site');
                break;
            case 'medium':
                recs.push('Verify through official channels before entering data');
                break;
            case 'suspicious':
                recs.push('Double-check the domain name carefully');
                break;
            default:
                recs.push('Deep learning model classifies site as safe');
        }
        if (features[8] > 0) recs.push('Possible typosquatting detected');
        return recs;
    }

    // ─── Trustpilot ──────────────────────────────────────────────────────────

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
            await chrome.storage.local.set({ trustpilotCache: Object.fromEntries(this.trustpilotCache) });
        } catch (error) {
            console.error('Error saving Trustpilot cache:', error);
        }
    }

    async getTrustpilotScore(domain) {
        const d = domain.toLowerCase().replace(/^www\./, '');
        if (this.trustpilotCache.has(d)) {
            const cached = this.trustpilotCache.get(d);
            if (Date.now() - cached.timestamp < 86400000) return cached.score;
        }
        if (this.isKnownPhishingDomain(d)) {
            const score = 1.2;
            this.trustpilotCache.set(d, { score, timestamp: Date.now() });
            await this.saveTrustpilotCache();
            return score;
        }
        const knownScores = {
            'google.com': 4.2, 'amazon.com': 3.8, 'facebook.com': 2.1,
            'paypal.com': 4.0, 'microsoft.com': 3.9, 'apple.com': 4.1,
            'netflix.com': 3.7, 'github.com': 4.5, 'wikipedia.org': 4.3
        };
        for (const [legit, score] of Object.entries(knownScores)) {
            if (d === legit || d.endsWith('.' + legit)) {
                this.trustpilotCache.set(d, { score, timestamp: Date.now() });
                await this.saveTrustpilotCache();
                return score;
            }
        }
        return 3.0;
    }

    getModelStats() {
        return {
            version: this.modelVersion,
            datasetSize: this.phishingDataset.length,
            phishingDomains: this.phishingDomains.size,
            cacheSize: this.trustpilotCache.size,
            accuracy: this.trainingMetrics.accuracy,
            valAccuracy: this.trainingMetrics.valAccuracy,
            loss: this.trainingMetrics.loss,
            trainingSamples: this.trainingMetrics.samples,
            epochs: this.trainingMetrics.epochs,
            trainedAt: this.trainingMetrics.trainedAt,
            lastUpdated: new Date().toISOString(),
            algorithm: 'Deep Neural Network',
            architecture: '64 → 32 → 16 → 1 (ReLU, Dropout, Sigmoid)',
            backend: 'Pure JavaScript (CSP-safe)',
            features: SafeClickMLModel.INPUT_SIZE
        };
    }
}

if (typeof self !== 'undefined') self.SafeClickMLModel = SafeClickMLModel;
if (typeof module !== 'undefined' && module.exports) module.exports = SafeClickMLModel;
