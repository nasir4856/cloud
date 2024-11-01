import os
import subprocess
import requests
import zipfile
import time

BLACKLIST_URL = "https://myip.ms/files/blacklist/general/full_blacklist_database.zip"
BLACKLIST_ZIP_PATH = "/tmp/full_blacklist_database.zip"
BLACKLIST_TXT_PATH = "/tmp/full_blacklist_database.txt"

def install_dependencies():
    """Install required packages for iptables, Apache modules, and requests."""
    print("Installing dependencies...")
    subprocess.run(["sudo", "yum", "-y", "install", "iptables-services", "mod_evasive", "httpd"])
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
    """Parse the blacklist and return a set of IPs."""
    with open(BLACKLIST_TXT_PATH, "r") as f:
        ip_list = {line.strip() for line in f if line.strip() and not line.startswith("#")}
    print(f"{len(ip_list)} IPs parsed from blacklist.")
    return ip_list

def block_ip(ip):
    """Block a single IP using iptables."""
    subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"])
    print(f"Blocked IP: {ip}")

def apply_blacklist(ip_list):
    """Apply the blacklist by blocking each IP."""
    print("Applying blacklist...")
    for ip in ip_list:
        block_ip(ip)

def refined_rate_limit():
    """Apply refined rate limits using iptables."""
    print("Setting refined rate limits with iptables...")
    subprocess.run(["sudo", "iptables", "-F"])
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

def configure_mod_evasive():
    """Configure Apache's mod_evasive module for rate limiting."""
    print("Configuring mod_evasive...")
    mod_evasive_conf = """
<IfModule mod_evasive20.c>
    DOSHashTableSize 3097
    DOSPageCount 20
    DOSSiteCount 200
    DOSPageInterval 1
    DOSSiteInterval 1
    DOSBlockingPeriod 10
    DOSEmailNotify youremail@example.com
    DOSLogDir "/var/log/mod_evasive"
</IfModule>
"""
    with open("/etc/httpd/conf.d/mod_evasive.conf", "w") as f:
        f.write(mod_evasive_conf)
    subprocess.run(["sudo", "systemctl", "restart", "httpd"])
    print("mod_evasive configured and Apache restarted.")

def setup_security_group():
    """Configure AWS Security Group (if AWS CLI is installed and configured)."""
    print("Configuring AWS Security Group...")
    security_group_id = "YOUR_SECURITY_GROUP_ID"  # Replace with your SG ID
    # Allow HTTP, HTTPS, and SSH
    subprocess.run(["aws", "ec2", "authorize-security-group-ingress", "--group-id", security_group_id,
                    "--protocol", "tcp", "--port", "80", "--cidr", "0.0.0.0/0"])
    subprocess.run(["aws", "ec2", "authorize-security-group-ingress", "--group-id", security_group_id,
                    "--protocol", "tcp", "--port", "443", "--cidr", "0.0.0.0/0"])
    subprocess.run(["aws", "ec2", "authorize-security-group-ingress", "--group-id", security_group_id,
                    "--protocol", "tcp", "--port", "22", "--cidr", "YOUR_IP/32"])  # Replace YOUR_IP with your own IP
    print("AWS Security Group configured.")

def main():
    install_dependencies()
    download_blacklist()
    unzip_blacklist()
    ip_list = parse_blacklist()
    apply_blacklist(ip_list)
    refined_rate_limit()
    configure_mod_evasive()
    setup_security_group()
    print("Firewall, Apache, and Security Group configuration complete.")

if __name__ == "__main__":
    main()
