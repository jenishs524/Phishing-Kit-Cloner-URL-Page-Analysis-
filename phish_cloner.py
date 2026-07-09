#!/usr/bin/env python3
"""
Project 26 – Phishing Kit Cloner
Downloads a page, analyses forms and suspicious elements.
"""

import sys
import os
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import jinja2
from datetime import datetime

# ---------- CONFIG ----------
URL = sys.argv[1] if len(sys.argv) > 1 else None
OUTPUT_DIR = "cloned_page"
REPORT_FILE = "phish_report.html"

if not URL:
    print("Usage: python phish_cloner.py <url>")
    print("Example: python phish_cloner.py https://suspicious-login-page.com")
    sys.exit(1)

os.makedirs(OUTPUT_DIR, exist_ok=True)

def fetch_page(url):
    try:
        resp = requests.get(url, timeout=15, verify=False)
        resp.raise_for_status()
        return resp.text, resp.url
    except Exception as e:
        print(f"[!] Error fetching {url}: {e}")
        return None, None

def save_page(html, url):
    # Save the HTML
    with open(os.path.join(OUTPUT_DIR, "index.html"), 'w', encoding='utf-8') as f:
        f.write(html)
    print(f"[*] Page saved to {OUTPUT_DIR}/index.html")

def analyse_page(html, base_url):
    soup = BeautifulSoup(html, 'html.parser')
    findings = []
    suspicious_forms = []

    # 1. Find all forms
    forms = soup.find_all('form')
    for form in forms:
        action = form.get('action')
        if action:
            full_action = urljoin(base_url, action)
            parsed = urlparse(full_action)
            if parsed.scheme != 'https':
                suspicious_forms.append({
                    "action": full_action,
                    "reason": "Form action uses HTTP (not HTTPS)"
                })
            elif not parsed.netloc.endswith(urlparse(base_url).netloc):
                suspicious_forms.append({
                    "action": full_action,
                    "reason": "Form action points to external domain"
                })
        # Check for password fields
        if form.find('input', {'type': 'password'}):
            findings.append("Password field found – possible credential harvester")

    # 2. Look for brand logos
    logos = soup.find_all('img', src=True)
    brand_indicators = ["logo", "brand", "company", "bank", "paypal", "amazon"]
    for img in logos:
        src = img.get('src', '').lower()
        alt = img.get('alt', '').lower()
        if any(b in src or b in alt for b in brand_indicators):
            findings.append(f"Brand logo/indicator found: {img.get('src')}")

    # 3. Check for suspicious external resources
    scripts = soup.find_all('script', src=True)
    for script in scripts:
        src = script.get('src')
        if src and not src.startswith('https://'):
            findings.append(f"Suspicious script source (non-HTTPS): {src}")

    # 4. Look for obvious phishing keywords
    text = soup.get_text().lower()
    phishing_keywords = ["verify", "account", "update", "security", "confirm", "login"]
    for kw in phishing_keywords:
        if kw in text:
            findings.append(f"Phishing keyword found: '{kw}'")

    return {
        "forms": suspicious_forms,
        "findings": findings,
        "total_forms": len(forms),
        "total_scripts": len(scripts),
        "total_images": len(logos)
    }

def generate_report(url, analysis):
    template = """
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Phishing Analysis Report</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, sans-serif; background: #f0f2f5; padding:20px; }
        .container { max-width:1200px; margin:auto; background:white; padding:30px; border-radius:12px; }
        h1 { color:#1a1a2e; border-bottom:3px solid #dc3545; padding-bottom:10px; }
        .summary { display:flex; gap:20px; margin:20px 0; }
        .card { padding:15px 20px; border-radius:8px; flex:1; text-align:center; color:white; }
        .card-info { background:#17a2b8; }
        .card-warn { background:#ffc107; color:#333; }
        .card-danger { background:#dc3545; }
        ul { list-style:none; padding:0; }
        li { background:#f8f9fa; margin:4px 0; padding:8px; border-left:3px solid #4a90e2; }
        .finding { border-left-color:#dc3545; }
        .form-suspicious { border-left-color:#ffc107; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔍 Phishing Kit Analysis</h1>
        <p><strong>URL:</strong> {{ url }}</p>
        <p><strong>Generated:</strong> {{ timestamp }}</p>
        <div class="summary">
            <div class="card card-info">Forms: {{ analysis.total_forms }}</div>
            <div class="card card-warn">Suspicious Forms: {{ analysis.forms|length }}</div>
            <div class="card card-danger">Findings: {{ analysis.findings|length }}</div>
        </div>
        <h2>Suspicious Forms</h2>
        <ul>
            {% for f in analysis.forms %}
            <li class="form-suspicious"><strong>Action:</strong> {{ f.action }} – {{ f.reason }}</li>
            {% else %}
            <li>No suspicious forms found.</li>
            {% endfor %}
        </ul>
        <h2>Findings</h2>
        <ul>
            {% for f in analysis.findings %}
            <li class="finding">{{ f }}</li>
            {% else %}
            <li>No suspicious findings.</li>
            {% endfor %}
        </ul>
    </div>
</body>
</html>
    """
    t = jinja2.Template(template)
    html = t.render(
        url=URL,
        timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        analysis=analysis
    )
    with open(REPORT_FILE, 'w') as f:
        f.write(html)
    print(f"[*] Report saved to {REPORT_FILE}")

def main():
    print(f"[*] Fetching page: {URL}")
    html, final_url = fetch_page(URL)
    if not html:
        sys.exit(1)

    save_page(html, final_url)
    print("[*] Analysing page...")
    analysis = analyse_page(html, final_url)
    generate_report(final_url, analysis)
    print("[+] Analysis complete. Open phish_report.html in your browser.")

if __name__ == "__main__":
    main()