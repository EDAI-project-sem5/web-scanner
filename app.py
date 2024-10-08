import os
import threading
from flask import Flask, render_template
from flask_socketio import SocketIO
from url_discovery import discover_urls
from vulnerability.sql_injection import is_sql_injection_vulnerable
from vulnerability.xss import is_xss_vulnerable
from vulnerability.command_injection import is_command_injection_vulnerable
from vulnerability.directory_traversal import is_directory_traversal_vulnerable
from vulnerability.open_redirect import is_open_redirect_vulnerable
from vulnerability.sensitive_info import is_sensitive_info_disclosed
from vulnerability.csrf import is_csrf_vulnerable
from vulnerability.file_upload import is_file_upload_vulnerable
from vulnerability.http_headers import check_http_headers

app = Flask(__name__)
socketio = SocketIO(app)

vulnerability_descriptions = {
    "is_sql_injection_vulnerable": "SQL Injection: Allows an attacker to interfere with the queries that an application makes to its database.",
    "is_xss_vulnerable": "Cross-Site Scripting (XSS): Allows attackers to inject malicious scripts into web pages viewed by other users.",
    "is_command_injection_vulnerable": "Command Injection: An attacker can execute arbitrary commands on the host operating system via a vulnerable application.",
    "is_directory_traversal_vulnerable": "Directory Traversal: Allows attackers to access files and directories that are stored outside the web root folder.",
    "is_open_redirect_vulnerable": "Open Redirect: An attacker can redirect users to malicious sites by manipulating the URLs.",
    "is_sensitive_info_disclosed": "Sensitive Information Disclosure: Exposes sensitive information such as passwords or secret tokens.",
    "is_csrf_vulnerable": "Cross-Site Request Forgery (CSRF): Tricks the user into submitting a request that they did not intend to make.",
    "is_file_upload_vulnerable": "File Upload Vulnerability: Allows an attacker to upload files that can be executed on the server.",
    "check_http_headers": "HTTP Header Security: Checks for missing security-related HTTP headers."
}

def check_vulnerability(vuln_func, page_url, results):
    vulnerable = vuln_func(page_url)
    results.append({
        "name": vuln_func.__name__,
        "description": vulnerability_descriptions[vuln_func.__name__],
        "vulnerable": vulnerable
    })

def scan_website(url):
    discovered_urls = discover_urls(url)
    print(f"Discovered {len(discovered_urls)} URLs on {url}:\n")

    for i, discovered_url in enumerate(discovered_urls, start=1):
        print(f"{i}. {discovered_url}")

    for page_url in discovered_urls:
        print(f"\nScanning {page_url} for vulnerabilities...")
        vulnerabilities = []

        threads = []
        for vuln_check in [
            is_sql_injection_vulnerable,
            is_xss_vulnerable,
            is_command_injection_vulnerable,
            is_directory_traversal_vulnerable,
            is_open_redirect_vulnerable,
            is_sensitive_info_disclosed,
            is_csrf_vulnerable,
            is_file_upload_vulnerable,
            check_http_headers,
        ]:
            thread = threading.Thread(target=check_vulnerability, args=(vuln_check, page_url, vulnerabilities))
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

        socketio.emit('url_report', {'url': page_url, 'results': vulnerabilities})

@socketio.on('start_scan')
def handle_scan(data):
    url = data['url']
    socketio.emit('status_update', f"Starting scan for {url}...")
    scan_website(url)

@app.route('/')
def index():
    return render_template('index.html')

if __name__ == '__main__':
    socketio.run(app, debug=True)
