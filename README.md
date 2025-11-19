# Linux Auth Log Analyzer

A Python-based security analysis tool that detects failed login attempts by parsing the Linux `/var/log/auth.log` file.  
The script identifies suspicious IP addresses, counts login failures, and generates a clean summary report.

---

## 🔍 Features
- Downloads `/var/log/auth.log` from a remote Linux server using SSH/SFTP
- Detects failed password attempts and invalid login attempts
- Extracts attacker IP addresses using Regex
- Generates a timestamped summary report
- Prints findings in a human-friendly format

---

## 🛠 Technologies Used
- Python 3
- Paramiko (SSH & SFTP)
- Regex (`re` module)
- Ubuntu Linux VM

---

## 📦 Installation

```bash
git clone https://github.com/<your-username>/linux-auth-log-analyzer.git
cd linux-auth-log-analyzer
pip3 install -r requirements.txt
