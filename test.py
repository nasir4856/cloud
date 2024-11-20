import os
import subprocess
import requests
import zipfile
import ipaddress
from datetime import datetime

BLACKLIST_URL = "https://myip.ms/files/blacklist/general/full_blacklist_database.zip"
BLACKLIST_ZIP_PATH = "/tmp/full_blacklist_database.zip"
BLACKLIST_TXT_PATH = "/tmp/full_blacklist_database.txt"
BLOCKED_IPS_LOG_PATH = "/var/log/blocked_ips.log"  # Path to the log file

def install_dependencies():
    """Install required packages for iptables and requests."""
    print("Installing dependencies...")
    subprocess.run(["sudo", "yum", "-y", "install", "iptables-services", "httpd"])
    subprocess.run(["sudo", "pip3", "install", "requests"])

def download_blacklist():
    """Download the latest IP blacklist zip file."""
    print("Downloading IP blacklist...")
    response = requests.get(BLACKLIST_URL)
    with open(BLACKLIST_ZIP_PATH, "wb") as f:
        f.write(response.content)
    print("Blacklist downloaded.")

def unzip_blacklist():
    """Unzip the blacklist and extract the IP list."""
    print("Unzipping IP blacklist...")
    with zipfile.ZipFile(BLACKLIST_ZIP_PATH, 'r') as zip_ref:
        zip_ref.extractall("/tmp/")
    print("Blacklist unzipped.")

def parse_blacklist():
    """Parse the blacklist file and extract valid IPs."""
    valid_ips = set()
    with open(BLACKLIST_TXT_PATH, "r") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                # Extract IP part before any comment
                ip = line.split("#")[0].strip()
                try:
                    ipaddress.ip_address(ip)  # Validate if it's a valid IP address
                    valid_ips.add(ip)
                except ValueError:
                    print(f"Invalid IP skipped: {ip}")
    print(f"{len(valid_ips)} valid IPs parsed from the blacklist.")
    return valid_ips

def block_ip(ip):
    """Block a single IP using iptables and log the blocked IP."""
    result = subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], capture_output=True, text=True)
    if result.returncode != 0:
        print(f"Failed to block IP {ip}: {result.stderr}")
    else:
        print(f"Blocked IP: {ip}")
        log_blocked_ip(ip)

def log_blocked_ip(ip):
    """Log the blocked IP to the log file."""
    with open(BLOCKED_IPS_LOG_PATH, "a") as log_file:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_file.write(f"{timestamp} - Blocked IP: {ip}\n")

def apply_blacklist(ip_list):
    """Apply the blacklist by blocking each IP."""
    print("Applying blacklist...")
    subprocess.run(["sudo", "iptables", "-F"])  # Flush existing rules
    for ip in ip_list:
        print(f"Processing IP: {ip}")
        block_ip(ip)

def refined_rate_limit():
    """Apply refined rate limits using iptables."""
    print("Setting refined rate limits with iptables...")
    subprocess.run(["sudo", "iptables", "-F"])  # Clear existing rules
    subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", "127.0.0.1", "-j", "ACCEPT"])

    # HTTP rate limiting - 20 req/min with burst limit of 50
    subprocess.run(["sudo", "iptables", "-A", "INPUT", "-p", "tcp", "--dport", "80",
                    "-m", "state", "--state", "NEW", "-m", "recent", "--set"])
    subprocess.run(["sudo", "iptables", "-A", "INPUT", "-p", "tcp", "--dport", "80",
                    "-m", "state", "--state", "NEW", "-m", "recent", "--update",
                    "--seconds", "60", "--hitcount", "20", "-j", "DROP"])

    # HTTPS rate limiting - 15 req/min with burst limit of 30
    subprocess.run(["sudo", "iptables", "-A", "INPUT", "-p", "tcp", "--dport", "443",
                    "-m", "state", "--state", "NEW", "-m", "recent", "--set"])
    subprocess.run(["sudo", "iptables", "-A", "INPUT", "-p", "tcp", "--dport", "443",
                    "-m", "state", "--state", "NEW", "-m", "recent", "--update",
                    "--seconds", "60", "--hitcount", "15", "-j", "DROP"])

    # Temporary ban for abusive IPs
    subprocess.run(["sudo", "iptables", "-A", "INPUT", "-m", "recent", "--rcheck",
                    "--seconds", "300", "--hitcount", "50", "-j", "DROP"])
    subprocess.run(["sudo", "iptables", "-A", "INPUT", "-m", "recent", "--set"])
    subprocess.run(["sudo", "iptables", "-A", "INPUT", "-m", "state", "--state",
                    "ESTABLISHED,RELATED", "-j", "ACCEPT"])
    subprocess.run(["sudo", "iptables", "-A", "INPUT", "-j", "DROP"])

def main():
    install_dependencies()
    download_blacklist()
    unzip_blacklist()
    ip_list = parse_blacklist()
    apply_blacklist(ip_list)
    refined_rate_limit()
    print("Firewall configuration complete.")

if __name__ == "__main__":
    main()
