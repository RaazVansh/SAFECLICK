# Phish Shield Chrome Extension - Installation Guide

## 🚀 Quick Installation

### Step 1: Download the Extension
1. Download all the Phish Shield files to a folder on your computer
2. Make sure the folder contains all the necessary files (manifest.json, popup.html, etc.)

### Step 2: Enable Developer Mode in Chrome
1. Open Google Chrome
2. Navigate to `chrome://extensions/`
3. Toggle on "Developer mode" in the top-right corner

### Step 3: Load the Extension
1. Click "Load unpacked" button
2. Select the folder containing the Phish Shield files
3. The extension should now appear in your extensions list

### Step 4: Pin the Extension
1. Click the puzzle piece icon in Chrome toolbar
2. Find "Phish Shield - AI Phishing Detection"
3. Click the pin icon to keep it visible in your toolbar

## 🔧 Troubleshooting

### Extension Not Loading
- **Problem**: Extension shows "Error" status
- **Solution**: 
  - Check that all files are in the same folder
  - Ensure manifest.json is present and valid
  - Try refreshing the extensions page

### Icons Not Showing
- **Problem**: Extension icon appears as a generic icon
- **Solution**: 
  - Replace placeholder icon files with actual PNG images
  - Icons should be 16x16, 32x32, 48x48, and 128x128 pixels
  - Use a shield or security-themed design

### Dashboard Not Loading
- **Problem**: Dashboard takes too long to load or shows errors
- **Solution**:
  - Check internet connection (needed for Chart.js CDN)
  - Clear browser cache and reload
  - Try the improved dashboard script

### Charts Not Displaying
- **Problem**: Charts appear blank or don't load
- **Solution**:
  - Ensure internet connection is available
  - Check browser console for errors
  - Try refreshing the dashboard

## 📁 File Structure

Make sure your extension folder contains:

```
Phish Shield/
├── manifest.json              # Extension configuration
├── popup.html                # Main popup interface
├── dashboard.html            # Analytics dashboard
├── warning.html              # Phishing site warning page
├── settings.html             # Settings page
├── background.js             # Service worker
├── content.js               # Content script
├── scripts/
│   ├── popup.js             # Popup functionality
│   ├── dashboard-improved.js # Improved dashboard
│   ├── settings.js          # Settings functionality
│   └── ml-model.js          # Machine learning model
├── styles/
│   ├── popup.css            # Popup styling
│   ├── dashboard.css        # Dashboard styling
│   └── settings.css         # Settings styling
├── data/
│   └── phishing_site_urls.csv # ML training dataset
└── icons/
    ├── icon16.png           # 16x16 icon
    ├── icon32.png           # 32x32 icon
    ├── icon48.png           # 48x48 icon
    └── icon128.png          # 128x128 icon
```

## 🎨 Customizing Icons

### Creating Your Own Icons
1. Design a shield or security-themed icon
2. Create versions in these sizes: 16x16, 32x32, 48x48, 128x128 pixels
3. Save as PNG format
4. Replace the placeholder files in the `icons/` folder

### Icon Design Tips
- Use a shield, lock, or security symbol
- Keep it simple and recognizable at small sizes
- Use contrasting colors for visibility
- Test how it looks in the Chrome toolbar

## 🔒 Security Features

### What Phish Shield Protects Against
- **Phishing Sites**: Fake websites that steal credentials
- **Typosquatting**: Domains that look like legitimate sites
- **Suspicious URLs**: URLs with suspicious patterns
- **Malicious Content**: Pages with harmful scripts or forms

### How It Works
1. **Real-time Analysis**: Analyzes every website you visit
2. **AI/ML Detection**: Uses machine learning to detect threats
3. **Trustpilot Integration**: Checks site reputation
4. **Community Reports**: Learns from user reports
5. **Automatic Blocking**: Blocks high-risk sites

## 📊 Dashboard Features

### Analytics Dashboard
- **Threat Distribution**: Pie chart showing safe vs suspicious vs phishing sites
- **Daily Activity**: Line chart of browsing activity
- **Weekly Trends**: Bar chart of security trends
- **Site History**: Detailed log of all visited sites
- **Export Reports**: Download security reports as CSV

### Performance Improvements
- **Lazy Loading**: Charts load only when needed
- **Caching**: Reduces loading times
- **Error Handling**: Graceful fallbacks for errors
- **Optimized Updates**: Efficient data updates

## 🤖 Machine Learning Features

### ML Model Capabilities
- **Feature Extraction**: Analyzes URLs, domains, and content
- **Threat Scoring**: Calculates risk scores for websites
- **Pattern Recognition**: Identifies phishing patterns
- **Continuous Learning**: Improves with user feedback

### Training Data
- **Phishing Dataset**: 100+ known phishing URLs
- **Feature Engineering**: Advanced threat indicators
- **Model Updates**: Regular model improvements

## 🛠️ Advanced Configuration

### Settings Options
- **Detection Sensitivity**: Adjust threat detection levels
- **Notifications**: Customize alert preferences
- **Auto-Blocking**: Enable/disable automatic site blocking
- **Data Management**: Export or clear browsing data

### Privacy Settings
- **Local Storage**: All data stored locally
- **No Tracking**: No personal data sent to servers
- **Community Protection**: Share only domain names for protection

## 📞 Support

### Getting Help
1. **Check Console**: Open browser console for error messages
2. **Refresh Extension**: Reload the extension in chrome://extensions/
3. **Clear Cache**: Clear browser cache and try again
4. **Check Files**: Ensure all files are present and valid

### Common Issues
- **Extension Disabled**: Re-enable in chrome://extensions/
- **Permission Errors**: Grant necessary permissions when prompted
- **Performance Issues**: Use the improved dashboard script
- **Chart Loading**: Check internet connection for Chart.js

## 🔄 Updates

### Updating the Extension
1. Download the latest version
2. Replace old files with new ones
3. Go to chrome://extensions/
4. Click the refresh icon on Phish Shield
5. The extension will reload with updates

### Version History
- **v1.0.0**: Initial release with basic phishing detection
- **v1.1.0**: Added dashboard and analytics
- **v1.2.0**: Improved performance and ML integration
- **v1.3.0**: Trustpilot integration and enhanced UI

---

**Phish Shield - Your AI-powered shield against phishing attacks**

For more help, check the main README.md file or contact support.
