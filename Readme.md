# 🛡️ Phishing Link Scanner

A lightweight Python tool to analyze URLs and detect potential phishing attempts based on URL structure, SSL usage, and page content.

## 🚀 Features

- Detects suspicious patterns such as:
  - IP address in URL
  - Use of URL shortening services
  - Missing HTTPS or SSL certificate
  - Phishing-related keywords in the page title
- Scores and classifies the risk level
- Easy to extend with APIs like PhishTank or Google Safe Browsing

## 🧰 Requirements

Install the required Python libraries:

```bash
pip install requests beautifulsoup4 tldextract
