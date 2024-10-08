import threading
from url_discovery import discover_urls
from vulnerability.sql_injection import is_sql_injection_vulnerable
from vulnerability.xss import is_xss_vulnerable
from vulnerability.command_injection import is_command_injection_vulnerable
from vulnerability.directory_traversal import is_directory_traversal_vulnerable
from vulnerability.open_redirect import is_open_redirect_vulnerable
from vulnerability.sensitive_info import is_sensitive_info_disclosed
from vulnerability.csrf import is_csrf_vulnerable
from vulnerability.file_upload import is_file_upload_vulnerable
# from vulnerability.session_management import is_session_management_vulnerable
from vulnerability.http_headers import check_http_headers

def check_vulnerability(vuln_func, page_url, results):
    if vuln_func(page_url):
        results.append(vuln_func.__name__)

def scan_website(url):
    # Step 1: Discover URLs on the website
    discovered_urls = discover_urls(url)
    print(f"Discovered {len(discovered_urls)} URLs on {url}:\n")
    
    for i, discovered_url in enumerate(discovered_urls, start=1):
        print(f"{i}. {discovered_url}")

    # Step 2: Scan each URL for multiple vulnerabilities
    for page_url in discovered_urls:
        print(f"\nScanning {page_url} for vulnerabilities...")
        vulnerabilities = []

        threads = []
        # Create threads for each vulnerability check
        for vuln_check in [
            is_sql_injection_vulnerable,
            is_xss_vulnerable,
            is_command_injection_vulnerable,
            is_directory_traversal_vulnerable,
            is_open_redirect_vulnerable,
            is_sensitive_info_disclosed,
            is_csrf_vulnerable,
            is_file_upload_vulnerable,
            # is_session_management_vulnerable,
            check_http_headers,
        ]:
            thread = threading.Thread(target=check_vulnerability, args=(vuln_check, page_url, vulnerabilities))
            threads.append(thread)
            thread.start()

        # Wait for all threads to complete
        for thread in threads:
            thread.join()

        # Report detected vulnerabilities
        if vulnerabilities:
            print(f"Vulnerabilities found on {page_url}:")
            for vuln in vulnerabilities:
                print(f" - {vuln}")
        else:
            print(f"No vulnerabilities found on {page_url}.")

# Example usage
if __name__ == "__main__":
    scan_website("https://www.vit.edu")
