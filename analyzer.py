import paramiko
import re
import argparse
import getpass
from datetime import datetime


def download_auth_log(ssh_client, remote_path, local_path):
    """Downloads the auth log file from the remote server."""
    try:
        sftp = ssh_client.open_sftp()
        print(f"[+] Downloading log file from {remote_path} ...")
        sftp.get(remote_path, local_path)
        sftp.close()
        print(f"[+] Log saved locally as: {local_path}")
    except Exception as e:
        print(f"[ERROR] Could not download file: {e}")
        raise


def parse_auth_log(local_path):
    """Parses the downloaded auth.log file for failed login attempts."""
    failed_attempts = []
    ip_pattern = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})")  # IPv4 regex

    try:
        with open(local_path, "r", encoding="utf-8", errors="ignore") as file:
            for line in file:
                if "Failed password" in line or "Invalid user" in line:
                    ip_match = ip_pattern.search(line)
                    if ip_match:
                        failed_attempts.append(ip_match.group(1))
    except Exception as e:
        print(f"[ERROR] Unable to read log file: {e}")
        raise

    return failed_attempts


def generate_report(ips):
    """Creates a timestamped summary report of failed attempts."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_name = f"auth_summary_{timestamp}.txt"

    with open(report_name, "w") as report:
        report.write("=== Authentication Log Summary ===\n")
        report.write(f"Generated: {timestamp}\n\n")
        report.write(f"Total Failed Login Attempts: {len(ips)}\n\n")

        if ips:
            report.write("Top Offending IP Addresses:\n")
            unique_ips = sorted(set(ips), key=ips.count, reverse=True)
            for ip in unique_ips:
                report.write(f"- {ip}  ({ips.count(ip)} attempts)\n")
        else:
            report.write("No failed login attempts found.\n")

    print(f"[+] Report generated: {report_name}")


def establish_ssh(host, user, password=None, key_path=None, port=22):
    """Creates an SSH connection using password or key."""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        if key_path:
            key = paramiko.RSAKey.from_private_key_file(key_path)
            client.connect(host, port=port, username=user, pkey=key)
        else:
            client.connect(host, port=port, username=user, password=password)

        print(f"[+] Connected to {host}")
        return client

    except Exception as e:
        print(f"[ERROR] SSH connection failed: {e}")
        raise


def main():
    parser = argparse.ArgumentParser(description="Linux Auth Log Analyzer Tool")
    parser.add_argument("--host", required=True, help="Target server IP")
    parser.add_argument("--user", required=True, help="SSH username")
    parser.add_argument("--port", default=22, type=int, help="SSH port")
    parser.add_argument("--password", help="SSH password (optional)")
    parser.add_argument("--key", help="SSH private key path (optional)")
    parser.add_argument("--remote-path", default="/var/log/auth.log",
                        help="Remote auth log path")
    parser.add_argument("--local-path", default="auth.log",
                        help="Local file path to save downloaded log")

    args = parser.parse_args()

    # If no password and no key, ask securely
    password = args.password
    if not password and not args.key:
        password = getpass.getpass("SSH Password: ")

    print("[+] Establishing SSH connection...")
    ssh_client = establish_ssh(
        host=args.host,
        user=args.user,
        password=password,
        key_path=args.key,
        port=args.port
    )

    print("[+] Downloading authentication log...")
    download_auth_log(ssh_client, args.remote_path, args.local_path)

    print("[+] Parsing authentication log for failed attempts...")
    failed_ips = parse_auth_log(args.local_path)

    print("[+] Generating report...")
    generate_report(failed_ips)

    ssh_client.close()
    print("[+] SSH session closed. Task completed successfully.")


if __name__ == "__main__":
    main()
