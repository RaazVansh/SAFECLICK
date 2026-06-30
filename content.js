// Phish Shield - Content Script
class SafeClickContent {
    constructor() {
        this.currentUrl = window.location.href;
        this.domain = this.extractDomain(this.currentUrl);
        this.init();
    }

    init() {
        this.analyzePageContent();
        this.setupEventListeners();
        this.injectSafetyIndicator();
    }

    extractDomain(url) {
        try {
            const urlObj = new URL(url);
            return urlObj.hostname;
        } catch {
            return 'unknown';
        }
    }

    async analyzePageContent() {
        // Analyze page content for phishing indicators
        const indicators = this.detectPhishingIndicators();
        
        if (indicators.length > 0) {
            // Send analysis results to background script
            chrome.runtime.sendMessage({
                action: 'contentAnalysis',
                url: this.currentUrl,
                domain: this.domain,
                indicators: indicators
            });
        }
    }

    detectPhishingIndicators() {
        const indicators = [];
        
        // Check for login forms
        const loginForms = document.querySelectorAll('input[type="password"], input[name*="password"], input[name*="passwd"]');
        if (loginForms.length > 0) {
            indicators.push('login_form_detected');
        }
        
        // Check for suspicious keywords in page content
        const suspiciousKeywords = [
            'verify', 'confirm', 'update', 'secure', 'account', 'login', 'signin',
            'password', 'credit card', 'banking', 'paypal', 'amazon', 'ebay'
        ];
        
        const pageText = document.body.innerText.toLowerCase();
        const foundKeywords = suspiciousKeywords.filter(keyword => 
            pageText.includes(keyword)
        );
        
        if (foundKeywords.length > 3) {
            indicators.push('suspicious_keywords');
        }
        
        // Check for external scripts
        const externalScripts = document.querySelectorAll('script[src]');
        const suspiciousDomains = ['cdn.example.com', 'js.malicious.com'];
        
        externalScripts.forEach(script => {
            const src = script.src;
            if (suspiciousDomains.some(domain => src.includes(domain))) {
                indicators.push('external_suspicious_script');
            }
        });
        
        // Check for popup attempts
        if (window.opener || window.name.includes('popup')) {
            indicators.push('popup_window');
        }
        
        // Check for urgency indicators
        const urgencyWords = ['urgent', 'immediate', 'now', 'limited time', 'expires'];
        const urgencyFound = urgencyWords.filter(word => 
            pageText.includes(word)
        );
        
        if (urgencyFound.length > 0) {
            indicators.push('urgency_indicators');
        }
        
        // Check for reward promises
        const rewardWords = ['free', 'prize', 'winner', 'reward', 'bonus', 'claim'];
        const rewardFound = rewardWords.filter(word => 
            pageText.includes(word)
        );
        
        if (rewardFound.length > 0) {
            indicators.push('reward_promises');
        }
        
        // Check for form submission to suspicious domains
        const forms = document.querySelectorAll('form');
        forms.forEach(form => {
            const action = form.action;
            if (action && !action.startsWith('http')) {
                // Relative form action - check if it's suspicious
                if (form.querySelector('input[type="password"]')) {
                    indicators.push('password_form_relative_action');
                }
            }
        });
        
        return indicators;
    }

    setupEventListeners() {
        // Monitor form submissions
        document.addEventListener('submit', (event) => {
            this.handleFormSubmission(event);
        });
        
        // Monitor link clicks
        document.addEventListener('click', (event) => {
            this.handleLinkClick(event);
        });
        
        // Monitor password field interactions
        document.addEventListener('input', (event) => {
            if (event.target.type === 'password') {
                this.handlePasswordInput(event);
            }
        });
    }

    handleFormSubmission(event) {
        const form = event.target;
        const hasPassword = form.querySelector('input[type="password"]');
        
        if (hasPassword) {
            // Check if this is a suspicious form submission
            const formData = new FormData(form);
            const action = form.action;
            
            chrome.runtime.sendMessage({
                action: 'formSubmission',
                url: this.currentUrl,
                formAction: action,
                hasPassword: true
            });
        }
    }

    handleLinkClick(event) {
        const link = event.target.closest('a');
        if (link && link.href) {
            const href = link.href;
            
            // Check if link is suspicious
            if (this.isSuspiciousLink(href)) {
                event.preventDefault();
                this.showLinkWarning(href);
            }
        }
    }

    isSuspiciousLink(href) {
        try {
            const url = new URL(href);
            const currentDomain = this.extractDomain(this.currentUrl);
            const linkDomain = url.hostname;
            
            // Check for domain mismatch
            if (linkDomain !== currentDomain && !linkDomain.includes(currentDomain)) {
                // Check for suspicious patterns
                const suspiciousPatterns = [
                    /bit\.ly/, /tinyurl\.com/, /goo\.gl/, /t\.co/,
                    /\d+\.\d+\.\d+\.\d+/, // IP addresses
                    /\.tk$|\.ml$|\.ga$|\.cf$|\.gq$/ // Suspicious TLDs
                ];
                
                return suspiciousPatterns.some(pattern => pattern.test(linkDomain));
            }
        } catch (error) {
            // Invalid URL
            return true;
        }
        
        return false;
    }

    showLinkWarning(href) {
        const warning = document.createElement('div');
        warning.className = 'safeclick-link-warning';
        warning.innerHTML = `
            <div class="warning-content">
                <i class="fas fa-exclamation-triangle"></i>
                <h3>Warning: Suspicious Link Detected</h3>
                <p>This link appears to be suspicious and may lead to a phishing site.</p>
                <p><strong>Link:</strong> ${href}</p>
                <div class="warning-actions">
                    <button class="btn-cancel">Cancel</button>
                    <button class="btn-proceed">Proceed Anyway</button>
                </div>
            </div>
        `;
        
        // Add styles
        const style = document.createElement('style');
        style.textContent = `
            .safeclick-link-warning {
                position: fixed;
                top: 0;
                left: 0;
                width: 100%;
                height: 100%;
                background: rgba(0, 0, 0, 0.8);
                z-index: 2147483645;
                display: flex;
                align-items: center;
                justify-content: center;
                font-family: Arial, sans-serif;
                pointer-events: auto;
            }
            .warning-content {
                background: white;
                padding: 30px;
                border-radius: 10px;
                max-width: 90vw;
                max-height: 90vh;
                text-align: center;
                box-shadow: 0 10px 30px rgba(0, 0, 0, 0.3);
                overflow: auto;
            }
            .warning-content i {
                color: #f59e0b;
                font-size: 48px;
                margin-bottom: 20px;
            }
            .warning-content h3 {
                color: #1e293b;
                margin-bottom: 15px;
            }
            .warning-content p {
                color: #64748b;
                margin-bottom: 10px;
                word-wrap: break-word;
            }
            .warning-actions {
                margin-top: 20px;
                display: flex;
                gap: 10px;
                justify-content: center;
                flex-wrap: wrap;
            }
            .btn-cancel, .btn-proceed {
                padding: 10px 20px;
                border: none;
                border-radius: 5px;
                cursor: pointer;
                font-weight: bold;
                transition: background 0.3s ease;
                min-width: 100px;
            }
            .btn-cancel {
                background: #ef4444;
                color: white;
            }
            .btn-cancel:hover {
                background: #dc2626;
            }
            .btn-proceed {
                background: #10b981;
                color: white;
            }
            .btn-proceed:hover {
                background: #059669;
            }
        `;
        
        document.head.appendChild(style);
        document.body.appendChild(warning);
        
        // Handle button clicks
        warning.querySelector('.btn-cancel').addEventListener('click', (e) => {
            e.preventDefault();
            e.stopPropagation();
            if (document.body.contains(warning)) {
                document.body.removeChild(warning);
            }
        });
        
        warning.querySelector('.btn-proceed').addEventListener('click', (e) => {
            e.preventDefault();
            e.stopPropagation();
            if (document.body.contains(warning)) {
                document.body.removeChild(warning);
            }
            window.location.href = href;
        });
    }

    handlePasswordInput(event) {
        // Monitor password field for suspicious activity
        const passwordField = event.target;
        const form = passwordField.closest('form');
        
        if (form) {
            // Check if password is being entered on a suspicious page
            chrome.runtime.sendMessage({
                action: 'passwordInput',
                url: this.currentUrl,
                domain: this.domain
            });
        }
    }

    injectSafetyIndicator() {
        // Add a small safety indicator to the page
        const indicator = document.createElement('div');
        indicator.className = 'safeclick-indicator';
        indicator.innerHTML = `
            <div class="indicator-content">
                <i class="fas fa-shield-alt"></i>
                <span>Phish Shield</span>
            </div>
        `;
        
        // Add styles
        const style = document.createElement('style');
        style.textContent = `
            .safeclick-indicator {
                position: fixed;
                top: 20px;
                right: 20px;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white;
                padding: 8px 12px;
                border-radius: 20px;
                font-size: 12px;
                font-weight: bold;
                z-index: 2147483647;
                cursor: pointer;
                box-shadow: 0 4px 15px rgba(0, 0, 0, 0.2);
                transition: all 0.3s ease;
                opacity: 0.8;
                pointer-events: auto;
                user-select: none;
                -webkit-user-select: none;
                -moz-user-select: none;
                -ms-user-select: none;
            }
            .safeclick-indicator:hover {
                opacity: 1;
                transform: scale(1.05);
            }
            .indicator-content {
                display: flex;
                align-items: center;
                gap: 5px;
                white-space: nowrap;
            }
            .indicator-content i {
                font-size: 14px;
            }
        `;
        
        document.head.appendChild(style);
        document.body.appendChild(indicator);
        
        // Make indicator clickable to show status
        indicator.addEventListener('click', (e) => {
            e.preventDefault();
            e.stopPropagation();
            this.showStatusPopup();
        });
    }

    showStatusPopup() {
        // Show a popup with current site status
        chrome.runtime.sendMessage({
            action: 'getSiteStatus',
            url: this.currentUrl
        }, (response) => {
            if (response && response.threatScore !== undefined) {
                this.displayStatusPopup(response.threatScore);
            }
        });
    }

    displayStatusPopup(threatScore) {
        const popup = document.createElement('div');
        popup.className = 'safeclick-status-popup';
        
        let status, color, icon;
        if (threatScore > 0.7) {
            status = 'High Risk';
            color = '#ef4444';
            icon = 'fas fa-times-circle';
        } else if (threatScore > 0.4) {
            status = 'Suspicious';
            color = '#f59e0b';
            icon = 'fas fa-exclamation-triangle';
        } else {
            status = 'Safe';
            color = '#10b981';
            icon = 'fas fa-shield-check';
        }
        
        popup.innerHTML = `
            <div class="status-content">
                <i class="${icon}" style="color: ${color}"></i>
                <h3>Site Status: ${status}</h3>
                <p>Threat Score: ${Math.round(threatScore * 100)}%</p>
                <button class="close-btn">Close</button>
            </div>
        `;
        
        // Add styles
        const style = document.createElement('style');
        style.textContent = `
            .safeclick-status-popup {
                position: fixed;
                top: 50%;
                left: 50%;
                transform: translate(-50%, -50%);
                background: white;
                padding: 30px;
                border-radius: 15px;
                box-shadow: 0 20px 40px rgba(0, 0, 0, 0.3);
                z-index: 2147483646;
                text-align: center;
                font-family: Arial, sans-serif;
                max-width: 90vw;
                max-height: 90vh;
                overflow: auto;
                pointer-events: auto;
            }
            .status-content i {
                font-size: 48px;
                margin-bottom: 15px;
            }
            .status-content h3 {
                color: #1e293b;
                margin-bottom: 10px;
            }
            .status-content p {
                color: #64748b;
                margin-bottom: 20px;
            }
            .close-btn {
                background: #667eea;
                color: white;
                border: none;
                padding: 10px 20px;
                border-radius: 5px;
                cursor: pointer;
                font-weight: bold;
                transition: background 0.3s ease;
            }
            .close-btn:hover {
                background: #5a67d8;
            }
        `;
        
        document.head.appendChild(style);
        document.body.appendChild(popup);
        
        // Handle close button
        popup.querySelector('.close-btn').addEventListener('click', (e) => {
            e.preventDefault();
            e.stopPropagation();
            if (document.body.contains(popup)) {
                document.body.removeChild(popup);
            }
        });
        
        // Close on background click
        popup.addEventListener('click', (e) => {
            if (e.target === popup) {
                if (document.body.contains(popup)) {
                    document.body.removeChild(popup);
                }
            }
        });
        
        // Auto-close after 5 seconds
        setTimeout(() => {
            if (document.body.contains(popup)) {
                document.body.removeChild(popup);
            }
        }, 5000);
    }
}

// Initialize content script
new SafeClickContent();
