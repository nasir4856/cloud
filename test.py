import os
import subprocess
import requests

def install_dependencies():
    """Install required packages for iptables and requests."""
    print("Installing dependencies...")
    subprocess.run(["sudo", "yum", "-y", "install", "iptables-services", "httpd"])
    subprocess.run(["sudo", "pip3", "install", "requests"])

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

def setup_security_group():
    """Configure AWS Security Group (if AWS CLI is installed and configured)."""
    print("Configuring AWS Security Group...")
    security_group_id = "sg-0bc74359cce8c747a"  # Replace with your Security Group ID
    subprocess.run(["aws", "ec2", "authorize-security-group-ingress", "--group-id", security_group_id,
                    "--protocol", "tcp", "--port", "80", "--cidr", "0.0.0.0/0"])
    subprocess.run(["aws", "ec2", "authorize-security-group-ingress", "--group-id", security_group_id,
                    "--protocol", "tcp", "--port", "443", "--cidr", "0.0.0.0/0"])
    subprocess.run(["aws", "ec2", "authorize-security-group-ingress", "--group-id", security_group_id,
                    "--protocol", "tcp", "--port", "22", "--cidr", "0.0.0.0/0"])
    print("AWS Security Group configured.")

def main():
    install_dependencies()
    refined_rate_limit()
    setup_security_group()
    print("Firewall and Security Group configuration complete.")

if __name__ == "__main__":
    main()
