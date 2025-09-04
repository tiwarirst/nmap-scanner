# 🛡️ Interactive Nmap Vulnerability Scanner

An **interactive, user-friendly** Python-based Nmap wrapper that helps you **scan targets**, **analyze open ports**, and **get vulnerability hints** based on detected services and versions.  
Designed for penetration testers, cybersecurity learners, and network administrators.

---

## � Prerequisites

- Python 3.8 or higher
- Nmap installed on your system (see installation instructions below)
- Administrative privileges for certain scan types (OS detection, SYN scans)

### Installing Nmap

#### Windows
1. Download Nmap from [nmap.org/download.html](https://nmap.org/download.html)
2. Run the installer (e.g., `nmap-7.94-setup.exe`) with administrator privileges
3. Check "Add Nmap directory to PATH" during installation
4. Install WinPcap when prompted
5. Restart your computer after installation

#### Linux (Debian/Ubuntu)
```bash
sudo apt update
sudo apt install nmap
```

#### macOS
```bash
brew install nmap
```

## �🚀 Features
- **Multiple Scan Modes**
  - Common ports scan
  - All ports scan
  - Custom ports scan
  - Aggressive scan (`-A`) for OS & version detection
- **Interactive Menu**
  - Choose scan type from a list
  - Re-run with different flags if needed
- **Version Detection**
  - Identifies service versions on open ports
- **Vulnerability Hints**
  - Suggests possible attacks based on service & version
- **Export Reports**
  - Save results in `.txt` or `.md` format
- **Colorful & Readable Output**
  - Uses `rich` for better CLI visualization

---

## 📦 Installation

### 1. Clone the Repository
```bash
git clone https://github.com/yourusername/interactive-nmap-scanner.git
cd interactive-nmap-scanner

Requirements:

## 🔧 Installation

1. Clone the repository
```bash
git clone <your-repo-url>
cd nmap-scanner
```

2. Create and activate a virtual environment

**Windows:**
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

**Linux/macOS:**
```bash
python3 -m venv .venv
source .venv/bin/activate
```

3. Install required Python packages
```bash
pip install python-nmap rich requests
```

## 💻 Usage

1. Activate the virtual environment (if not already activated)

2. Run the scanner:
```bash
python cnmap-scanner-assistance.py
```

3. Enter your target IP or domain when prompted (e.g., 192.168.1.10)

**USAGE**

Choose scan type:
[1] Common ports scan (fast)
[2] All ports scan (slow)
[3] Aggressive scan (-A)
[4] Custom port scan
[5] Exit

Select option: 2
Scanning 192.168.1.10 with Nmap flags: -p- -sV


OUTPUT

[+] Scanning Target: 192.168.1.10
[+] Open Ports Found:
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.6p1 Ubuntu 4
80/tcp   open  http    Apache httpd 2.4.29
3306/tcp open  mysql   MySQL 5.7.33

[!] Potential Vulnerabilities:
- OpenSSH 7.6p1: Possible brute-force attacks, outdated version.
- Apache 2.4.29: Known CVEs (CVE-2019-0211), potential DoS vulnerabilities.
- MySQL 5.7.33: Possible SQL injection vectors if web apps connect.

[+] Report saved to: scan_report_192.168.1.10.md


## 🛠️ Scan Modes & Flags

| Mode | Flags        | Description                                 | Required Privileges |
|------|--------------|---------------------------------------------|-------------------|
| 1    | `-F`         | Fast scan of common ports                   | Standard User |
| 2    | `-p- -sV`    | Scan all 65535 ports & detect versions     | Standard User |
| 3    | `-A`         | Aggressive scan (OS, version, scripts)      | Administrator/Root |
| 4    | `-p X,Y,Z`   | Custom port scan (specify ports)           | Standard User |

## 📝 Output Formats

The scanner can save reports in multiple formats:
- JSON (detailed machine-readable format)
- Markdown (formatted report with tables)
- HTML (web-viewable format)

Reports include:
- Open ports and services
- Service versions (when detected)
- Potential vulnerability suggestions
- CVE matches (when enabled)

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## ⚠️ Disclaimer

This tool is intended for educational purposes and authorized security assessments only.
The author assumes no responsibility for misuse or illegal activities.

Always ensure you have explicit permission to scan any target systems.
Some scan types may be considered intrusive and should only be used on systems you own or are authorized to test.
