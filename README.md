# 🛡️ AI-Powered Vulnerability Scanner

An automated cybersecurity vulnerability scanner that scrapes multiple sources, uses AI to analyze and structure data, and presents findings in an interactive dashboard.

## 🚀 Key Changes & Optimizations

### ✅ What Was Removed
- **NVD API Integration** - Removed `nvd.py` API calls to eliminate rate limiting and API key dependencies
- **Redundant Functions** - Cleaned up duplicate AI processing functions
- **Complex Report Summarization** - Simplified report generation workflow

### ✨ What Was Enhanced

#### 1. **Pure Scraping Architecture**
- All data now comes from web scraping (NVD website, CISA KEV catalog)
- More reliable and doesn't hit API rate limits
- Can easily add more sources without API keys

#### 2. **Optimized AI Parsing**
```python
parse_vulnerabilities_with_ai()  # Structured JSON extraction
generate_ai_insights()           # Strategic security analysis
find_mitigation()                # Instant remediation guidance
```

#### 3. **Enhanced Dashboard**
- **Modern UI** with gradient backgrounds and smooth animations
- **Interactive Charts**: Severity distribution & top affected products
- **Real-time Stats**: Total vulnerabilities, sources scanned, severity breakdown
- **AI Insights Panel**: Strategic security recommendations
- **Responsive Design**: Mobile-friendly layout

#### 4. **Improved Workflow**
```
Scan Trigger → Multi-Source Scraping → AI Processing → 
Deduplication → Report Generation → Dashboard Display
```

#### 5. **Better User Experience**
- Real-time progress tracking with 4-step indicator
- Animated scanning page with radar visualization
- Enhanced mitigation finder with better formatting
- Cleaner, more professional landing page

## 📦 Installation

```bash
# Clone repository
git clone <your-repo-url>
cd vulnerability-scanner

# Install dependencies
pip install -r requirements.txt

# Setup environment variables
echo "GOOGLE_API_KEY=your_gemini_api_key" > .env

# Run application
python app.py
```

## 🔑 Environment Variables

Create a `.env` file:

```env
GOOGLE_API_KEY=your_google_gemini_api_key
```

Get your API key: https://makersuite.google.com/app/apikey

## 🎯 Usage

1. **Start Application**
   ```bash
   python app.py
   ```

2. **Access Web Interface**
   - Open browser to `http://localhost:5000`
   - Click "Generate Vulnerability Report"

3. **View Results**
   - Wait for scan completion (2-5 minutes)
   - Explore interactive dashboard
   - Download text report
   - Use mitigation finder for specific CVEs

## 📊 Features

### 🌐 Multi-Source Scraping
- NVD Recent Vulnerabilities
- CISA Known Exploited Vulnerabilities
- Easily extensible for more sources

### 🤖 AI-Powered Analysis
- **Structured Parsing**: Extracts CVE ID, severity, CVSS, affected products
- **Deduplication**: Removes duplicate vulnerabilities
- **Smart Insights**: Identifies trends and priority actions
- **Mitigation Guidance**: Provides step-by-step remediation

### 📈 Interactive Dashboard
- Severity distribution pie chart
- Top affected products bar chart
- Detailed vulnerability table with filtering
- AI-generated security insights
- Timestamp tracking

### 🔍 Mitigation Finder
- Search by CVE ID or description
- Instant AI-powered solutions
- Reference links to official advisories
- Severity assessment

## 📁 Project Structure

```
├── app.py                    # Main Flask application
├── scrape.py                 # Web scraping logic
├── parse.py                  # AI parsing & analysis
├── report.py                 # Report generation
├── requirements.txt          # Python dependencies
├── .env                      # Environment variables
├── templates/
│   ├── index.html           # Landing page
│   ├── scanning.html        # Scan progress page
│   ├── dashboard.html       # Main dashboard
│   └── mitigation.html      # Mitigation finder
└── vulnerability_report.txt  # Generated report
└── vulnerability_report.json # Dashboard data
```

## ⚙️ Configuration

### Add More Sources

Edit `scrape.py`:

```python
def get_vulnerability_urls():
    return [
        "https://nvd.nist.gov/vuln/recent",
        "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
        "https://your-custom-source.com",  # Add here
    ]
```

### Adjust Scan Limits

Edit `app.py`:

```python
scraped_data = fetch_scraped_cves(limit=50)  # Change limit
combined = combined[:15]  # Number in final report
```

### Customize AI Model

Edit `parse.py`:

```python
llm = ChatGoogleGenerativeAI(
    model="gemini-2.0-flash-exp",  # Change model
    temperature=0.3                 # Adjust creativity
)
```

## 🔧 Troubleshooting

**Selenium Issues**
```bash
# Update ChromeDriver
pip install --upgrade webdriver-manager
```

**AI Parsing Errors**
- Check GOOGLE_API_KEY in .env
- Verify API quota limits
- Try reducing text size in parse.py

**No Data Scraped**
- Check internet connection
- Verify target websites are accessible
- Increase timeout in scrape.py

## 📝 Performance Notes

- **Scan Time**: 2-5 minutes depending on sources
- **Vulnerabilities**: Tracks 50+ CVEs per scan
- **Report Size**: ~300 lines (automatically summarized)
- **Memory**: < 500MB typical usage

## 🔒 Security Notes

- Report contains public CVE data only
- Always verify with official vendor advisories
- Use for educational/research purposes
- Keep dependencies updated

## 🎨 UI Highlights

- **Gradient Backgrounds**: Purple theme (#667eea → #764ba2)
- **Smooth Animations**: Hover effects, slide-ins, fades
- **Modern Cards**: Glassmorphism with shadows
- **Responsive Tables**: Mobile-optimized layouts
- **Interactive Charts**: Chart.js with custom styling

## 🚦 API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Landing page |
| `/scan` | POST | Trigger vulnerability scan |
| `/scanning` | GET | Scan progress page |
| `/status` | GET | Get scan status (JSON) |
| `/dashboard` | GET | View dashboard |
| `/mitigation` | GET | Mitigation finder page |
| `/api/vulnerabilities` | GET | Get vulnerability data (JSON) |
| `/api/mitigation` | POST | Find mitigation for CVE |
| `/get_report` | GET | Download text report |

## 📄 License

MIT License - Feel free to use and modify

## 🤝 Contributing

Contributions welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Submit a pull request

## 📧 Support

For issues or questions, please open a GitHub issue.

---

**Built with ❤️ using Flask, Selenium, Gemini AI, and Chart.js**