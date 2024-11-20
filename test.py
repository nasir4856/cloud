import os
import subprocess
import requests
import zipfile
import ipaddress
from datetime import datetime

BLOCKED_IPS_LOG_PATH = "/var/log/blocked_ips.log"  # Path to the log file

def install_dependencies():
    """Install required packages for iptables and requests."""
    print("Installing dependencies...")
    subprocess.run(["sudo", "yum", "-y", "install", "iptables-services", "httpd"])
    subprocess.run(["sudo", "pip3", "install", "requests"])

def refined_rate_limit():
    """Apply refined rate limits using iptables."""
    print("Setting refined rate limits with iptables...")
    subprocess.run(["sudo", "iptables", "-F"])  # Clear existing rules
    subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", "127.0.0.1", "-j", "ACCEPT"])  # Allow local traffic

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

    # Allow already established/related connections (e.g., responses to outgoing requests)
    subprocess.run(["sudo", "iptables", "-A", "INPUT", "-m", "state", "--state",
                    "ESTABLISHED,RELATED", "-j", "ACCEPT"])

    # Temporary ban for abusive IPs (rate-limited)
    subprocess.run(["sudo", "iptables", "-A", "INPUT", "-m", "recent", "--rcheck",
                    "--seconds", "300", "--hitcount", "50", "-j", "DROP"])
    subprocess.run(["sudo", "iptables", "-A", "INPUT", "-m", "recent", "--set"])

    # Block all other traffic after the rate limits are applied
    subprocess.run(["sudo", "iptables", "-A", "INPUT", "-j", "DROP"])

def log_blocked_ip(ip):
    """Log the blocked IP to the log file."""
    with open(BLOCKED_IPS_LOG_PATH, "a") as log_file:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_file.write(f"{timestamp} - Blocked IP: {ip}\n")

def block_ip(ip):
    """Block a single IP using iptables and log the blocked IP."""
    result = subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], capture_output=True, text=True)
    if result.returncode != 0:
        print(f"Failed to block IP {ip}: {result.stderr}")
    else:
        print(f"Blocked IP: {ip}")
        log_blocked_ip(ip)

def main():
    install_dependencies()
    refined_rate_limit()  # Apply rate limits
    print("Firewall configuration complete.")

if __name__ == "__main__":
    main()
