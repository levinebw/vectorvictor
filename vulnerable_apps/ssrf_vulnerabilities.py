"""
Server-Side Request Forgery (SSRF) Vulnerability Demo
OWASP A10:2021 - Server-Side Request Forgery
"""
import requests
import urllib.request
from flask import Flask, request

app = Flask(__name__)

@app.route('/fetch_url')
def fetch_url():
    """VULNERABLE: SSRF via URL parameter"""
    url = request.args.get('url')

    # VULNERABLE: No URL validation or whitelist
    try:
        response = requests.get(url)
        return response.text
    except Exception as e:
        return str(e), 400

@app.route('/proxy')
def proxy_request():
    """VULNERABLE: SSRF in proxy endpoint"""
    target_url = request.args.get('target')

    # VULNERABLE: Allows access to internal resources
    headers = {'User-Agent': 'ProxyBot/1.0'}
    response = requests.get(target_url, headers=headers)

    return response.content

@app.route('/webhook')
def trigger_webhook():
    """VULNERABLE: SSRF via webhook"""
    webhook_url = request.args.get('webhook_url')
    data = request.args.get('data', '{}')

    # VULNERABLE: No validation of webhook destination
    response = requests.post(webhook_url, data=data)
    return f"Webhook triggered: {response.status_code}"

@app.route('/import_feed')
def import_rss_feed():
    """VULNERABLE: SSRF in RSS feed import"""
    feed_url = request.args.get('feed')

    # VULNERABLE: Fetching arbitrary URLs
    response = urllib.request.urlopen(feed_url)
    content = response.read()

    return content

@app.route('/check_link')
def check_link():
    """VULNERABLE: SSRF in link checker"""
    link = request.args.get('link')

    # VULNERABLE: No blocklist for internal IPs
    try:
        response = requests.head(link, timeout=5)
        return {
            'status': response.status_code,
            'url': link
        }
    except:
        return {'error': 'Link unreachable'}, 400

def fetch_avatar(avatar_url):
    """VULNERABLE: SSRF in avatar fetching"""
    # VULNERABLE: No validation of avatar URL
    response = requests.get(avatar_url)

    if response.status_code == 200:
        return response.content
    return None

@app.route('/screenshot')
def take_screenshot():
    """VULNERABLE: SSRF in screenshot service"""
    page_url = request.args.get('url')

    # VULNERABLE: Could access internal services
    # Simulating screenshot service that fetches the URL
    response = requests.get(page_url)

    return f"Screenshot taken of {page_url}"

@app.route('/fetch_image')
def fetch_external_image():
    """VULNERABLE: SSRF in image fetching"""
    image_url = request.args.get('img')

    # VULNERABLE: No restriction on image source
    try:
        img_data = urllib.request.urlopen(image_url).read()
        return img_data
    except:
        return 'Failed to fetch image', 400

def download_file(file_url):
    """VULNERABLE: SSRF in file download"""
    # VULNERABLE: Can access cloud metadata endpoints
    # Example: http://169.254.169.254/latest/meta-data/
    response = requests.get(file_url)
    return response.content

@app.route('/pdf_generator')
def generate_pdf():
    """VULNERABLE: SSRF via PDF generation"""
    html_url = request.args.get('html')

    # VULNERABLE: PDF generator fetches arbitrary URLs
    # Could be used to access internal services
    html_content = requests.get(html_url).text

    return f"PDF generated from {html_url}"

@app.route('/preview')
def preview_url():
    """VULNERABLE: SSRF in URL preview"""
    url = request.args.get('url')

    # VULNERABLE: No validation against localhost, 127.0.0.1, or private IPs
    try:
        response = requests.get(url, timeout=10)
        return {
            'title': 'Preview',
            'content': response.text[:500],
            'status': response.status_code
        }
    except Exception as e:
        return {'error': str(e)}, 400

if __name__ == '__main__':
    # Example exploitation:
    # /fetch_url?url=http://localhost:8080/admin
    # /fetch_url?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/
    # /proxy?target=http://internal-service:5000/sensitive-data
    # /webhook?webhook_url=http://127.0.0.1:6379/  (Redis)
    app.run(debug=True)
