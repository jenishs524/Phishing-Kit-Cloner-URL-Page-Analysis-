📁 Phishing Kit Cloner (URL & Page Analysis)

Description
Downloads a suspicious webpage, analyses it for phishing indicators (forms, password fields, external/non‑HTTPS actions, brand logos, phishing keywords), and generates a report.

Key Features

    Downloads the page and saves it locally.

    Parses HTML with BeautifulSoup.

    Detects suspicious form actions, password fields, external resources.

    Identifies brand logos and phishing keywords.

    Generates an HTML report.

Technologies

    requests, BeautifulSoup, Jinja2.

Prerequisites

    Python 3.

Installation
bash

pip install requests beautifulsoup4 jinja2

Usage
bash

python phish_cloner.py https://suspicious-site.com

Sample Output
text

[*] Page saved to cloned_page/index.html
[*] Report saved to phish_report.html

Open phish_report.html to see findings.

Notes

    Use with caution – only on authorised or test sites.
