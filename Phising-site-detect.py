import re
import requests
import socket
import ssl
import tldextract
from bs4 import BeautifulSoup
from urllib.parse import urlparse

# List of known URL shortening services
SHORTENING_SERVICES = ['bit.ly', 'goo.gl', 'tinyurl.com', 'ow.ly', 't.co', 'bit.do']

# Suspicious words commonly used in phishing pages
SUSPICIOUS_KEYWORDS = ['login', 'verify', 'update', 'secure', 'account', 'bank', 'webscr', 'signin']

def is_ip_address(url):
    try:
        ip = urlparse(url).netloc
        socket.inet_aton(ip)
        return True
    except:
        return False

def is_shortened(url):
    domain = tldextract.extract(url).registered_domain
    return domain in SHORTENING_SERVICES

def has_https(url):
    return urlparse(url).scheme == "https"

def get_title(url):
    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.text, 'html.parser')
        return soup.title.string.lower() if soup.title else ""
    except:
        return ""

def keyword_in_title(title):
    return any(keyword in title for keyword in SUSPICIOUS_KEYWORDS)

def check_ssl_cert(url):
    try:
        parsed_url = urlparse(url)
        hostname = parsed_url.hostname
        port = 443
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                return cert is not None
    except:
        return False

def phishing_check(url):
    print(f"\nScanning URL: {url}")
    score = 0

    if is_ip_address(url):
        print("🔴 Suspicious: Uses IP address in URL")
        score += 1

    if is_shortened(url):
        print("🔴 Suspicious: Uses URL shortening service")
        score += 1

    if not has_https(url):
        print("🔴 Suspicious: Does not use HTTPS")
        score += 1

    if not check_ssl_cert(url):
        print("🔴 Suspicious: No valid SSL certificate")
        score += 1

    title = get_title(url)
    if keyword_in_title(title):
        print(f"🔴 Suspicious: Page title contains phishing keywords - '{title}'")
        score += 1

    # Verdict
    if score >= 3:
        print("⚠️ Verdict: Likely a phishing site")
    elif score == 2:
        print("🟠 Verdict: Possibly suspicious")
    else:
        print("🟢 Verdict: Looks safe (no major red flags)")

if __name__ == "__main__":
    url_input = input("Enter the URL to scan: ")
    phishing_check(url_input)
