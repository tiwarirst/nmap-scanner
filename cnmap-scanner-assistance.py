#!/usr/bin/env python3
"""
Interactive Nmap Reconnaissance Assistant

Features:
- Interactive menu to choose scan types (fast, full, -sV, -O, --script vuln, custom)
- Runs nmap commands (subprocess) and shows progress with Rich
- Parses nmap XML output to extract open ports, protocol, service, version
- Suggests likely vulnerability types & attack vectors based on service/port/version
- Can export report to JSON, Markdown, or HTML
- Optional: queries NVD (NIST) REST API for CVE matches (best-effort, rate-limited)

Requirements:
- nmap installed and available in PATH
- Python packages: rich, requests
  pip install rich requests

Run: python interactive_nmap_scanner.py

Note: Some scans (OS detection, full port scans) may require elevated privileges (run with sudo on Linux/macOS).

Author: Generated assistant
"""

import os
import re
import sys
import json
import time
import shlex
import socket
import subprocess
import threading
import tempfile
import xml.etree.ElementTree as ET
from datetime import datetime
from typing import List, Dict, Any, Optional

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.prompt import Prompt, Confirm
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
    from rich.markdown import Markdown
except Exception as e:
    print("Missing dependency 'rich'. Install with: pip install rich")
    raise

try:
    import requests
except Exception:
    print("Missing dependency 'requests'. Install with: pip install requests")
    raise

console = Console()

# ----------------------------- Utilities -----------------------------

def is_valid_ip_or_domain(target: str) -> bool:
    # Basic IPv4 validation
    try:
        socket.inet_aton(target)
        return True
    except Exception:
        pass
    # IPv6? simple check
    if ':' in target:
        try:
            socket.inet_pton(socket.AF_INET6, target)
            return True
        except Exception:
            pass
    # Domain name regex (simple)
    if re.match(r"^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[A-Za-z]{2,}$", target):
        return True
    return False


def run_subprocess(cmd: List[str], progress_task: Optional[Dict] = None, spinner_text: str = "Running") -> subprocess.CompletedProcess:
    """Run subprocess and return CompletedProcess. Show spinner in separate thread if needed."""
    # We run subprocess and stream stderr/stdout minimally; nmap will write to stdout
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    stdout_lines = []
    stderr_lines = []

    # Poll process and collect output
    try:
        while True:
            out = process.stdout.readline()
            if out:
                stdout_lines.append(out)
            err = process.stderr.readline()
            if err:
                stderr_lines.append(err)
            if out == '' and err == '' and process.poll() is not None:
                break
        rc = process.poll()
    except KeyboardInterrupt:
        process.terminate()
        raise

    return subprocess.CompletedProcess(cmd, rc, ''.join(stdout_lines), ''.join(stderr_lines))


def build_nmap_command(target: str, options: Dict[str, Any], output_xml: str) -> List[str]:
    # On Windows, look for nmap in its default installation path
    if os.name == 'nt':  # Windows
        nmap_path = r"C:\Program Files (x86)\Nmap\nmap.exe"
        if not os.path.exists(nmap_path):
            nmap_path = r"C:\Program Files\Nmap\nmap.exe"
        if not os.path.exists(nmap_path):
            raise FileNotFoundError("Could not find nmap.exe. Please install Nmap from https://nmap.org/download.html")
        base = [nmap_path, "-oX", output_xml]
    else:
        base = ["nmap", "-oX", output_xml]
    # Speed: not directly requested but we can include -T4 for faster scans unless user opts out
    # options contains booleans for different scan types and custom string
    if options.get("fast"):
        # common ports fast
        base += ["-F"]
    if options.get("full"):
        base += ["-p", "1-65535"]
    if options.get("service"):
        base += ["-sV"]
    if options.get("os"):
        base += ["-O"]
    if options.get("vuln_scripts"):
        base += ["--script", "vuln"]
    if options.get("custom_cmd"):
        # append custom parsed tokens (we expect a string)
        custom = shlex.split(options.get("custom_cmd"))
        base += custom
    # safe defaults
    if not any([options.get("fast"), options.get("full"), options.get("service"), options.get("os"), options.get("vuln_scripts"), options.get("custom_cmd")]):
        # default: common ports + service detection
        base += ["-sV", "-F"]
    base.append(target)
    return base


# ----------------------------- Parsing & Analysis -----------------------------


def parse_nmap_xml(xml_path: str) -> Dict[str, Any]:
    """Parse nmap XML output and return structured data."""
    tree = ET.parse(xml_path)
    root = tree.getroot()
    ns = ''
    result = {
        "scaninfo": {},
        "hosts": []
    }
    for host in root.findall('host'):
        host_dict = {"addresses": [], "ports": []}
        for addr in host.findall('address'):
            addrtype = addr.attrib.get('addrtype')
            address = addr.attrib.get('addr')
            host_dict['addresses'].append({'type': addrtype, 'addr': address})
        hostname_el = host.find('hostnames/hostname')
        if hostname_el is not None:
            host_dict['hostname'] = hostname_el.attrib.get('name')
        status = host.find('status')
        if status is not None:
            host_dict['status'] = status.attrib.get('state')
        ports = host.find('ports')
        if ports is not None:
            for port in ports.findall('port'):
                portid = port.attrib.get('portid')
                protocol = port.attrib.get('protocol')
                state_el = port.find('state')
                state = state_el.attrib.get('state') if state_el is not None else 'unknown'
                service_el = port.find('service')
                service = {}
                if service_el is not None:
                    service['name'] = service_el.attrib.get('name')
                    service['product'] = service_el.attrib.get('product')
                    service['version'] = service_el.attrib.get('version')
                    service['extrainfo'] = service_el.attrib.get('extrainfo')
                    service['ostype'] = service_el.attrib.get('ostype')
                port_dict = {
                    'port': int(portid),
                    'protocol': protocol,
                    'state': state,
                    'service': service
                }
                host_dict['ports'].append(port_dict)
        os_el = host.find('os')
        if os_el is not None:
            host_dict['osmatches'] = [o.attrib for o in os_el.findall('osmatch')]
        result['hosts'].append(host_dict)
    return result


# Simple database that maps services/ports to likely attacks & useful info
SERVICE_ATTACK_RULES = {
    'ftp': {
        'attacks': ['anonymous login', 'credential brute force', 'directory traversal', 'file upload leading to RCE'],
        'why': 'FTP often exposes file transfer and may allow anonymous or weak credentials, file upload, or misconfiguration.'
    },
    'ssh': {
        'attacks': ['credential brute force', 'private key misuse', 'SSH version specific crypto attacks'],
        'why': 'SSH provides remote command execution; weak creds or outdated versions compromise full system access.'
    },
    'http': {
        'attacks': ['SQL injection', 'Cross-site scripting (XSS)', 'Local/Remote File Inclusion (LFI/RFI)', 'RCE via vulnerable apps', 'Directory traversal'],
        'why': 'HTTP means a web application is present — the most common source of high-impact vulnerabilities.'
    },
    'https': {
        'attacks': ['same as HTTP', 'SSL/TLS misconfig (POODLE/Heartbleed style)', 'weak cipher downgrade'],
        'why': 'HTTPS adds TLS which can be misconfigured or outdated.'
    },
    'mysql': {
        'attacks': ['weak credentials', 'SQL injection (from app layer)', 'misconfigured remote DB access'],
        'why': 'Databases often contain sensitive data and may allow direct DB access if exposed.'
    },
    'mssql': {
        'attacks': ['brute force', 'MS-SQL injection', 'named pipe attacks'],
        'why': 'MS SQL Server exposures can allow data exfiltration and command execution via xp_cmdshell in some configurations.'
    },
    'rdp': {
        'attacks': ['brute force', 'bluekeep-like remote code exec (historical)', 'credential harvesting'],
        'why': 'RDP gives remote desktop access; compromised cred can mean full access.'
    },
    'smtp': {
        'attacks': ['open relay abuse', 'email spoofing', 'phishing vector', 'smtp auth brute force'],
        'why': 'SMTP servers can be abused to send spam or used as pivot for phishing.'
    },
    'snmp': {
        'attacks': ['info disclosure', 'community string brute force', 'configuration extraction'],
        'why': 'SNMP exposes device configuration and can leak sensitive data like routing and creds.'
    }
}


def suggest_attacks_for_service(service_name: Optional[str], port: int, version: Optional[str]) -> Dict[str, Any]:
    suggestions = {'service': service_name or 'unknown', 'port': port, 'version': version, 'attacks': [], 'why': ''}
    if not service_name:
        return suggestions
    key = service_name.lower()
    # map common aliases
    if key.startswith('http'):
        key = 'http'
    if key in SERVICE_ATTACK_RULES:
        suggestions['attacks'] = SERVICE_ATTACK_RULES[key]['attacks']
        suggestions['why'] = SERVICE_ATTACK_RULES[key]['why']
    else:
        # generic suggestions
        suggestions['attacks'] = ['fingerprinting & enumeration', 'version-specific CVE lookup', 'configuration checks']
        suggestions['why'] = 'Unknown service: enumerate further and check for version-specific CVEs.'
    # version-specific heuristics (simple examples)
    if version:
        if '2.3.4' in version and 'vsftpd' in (service_name or '').lower():
            suggestions['attacks'].append('backdoor in vsftpd 2.3.4 (historical exploit)')
        if '2.4.49' in version and 'apache' in (service_name or '').lower():
            suggestions['attacks'].append('path traversal / RCE in Apache 2.4.49 (CVE-2021-41773/4305)')
    return suggestions


# ----------------------------- CVE Lookup (Bonus) -----------------------------


def query_nvd_for_keyword(keyword: str, max_results: int = 5) -> List[Dict[str, Any]]:
    """Query NVD's public API for CVEs matching keyword. Rate-limited and best-effort.
    Uses: https://services.nvd.nist.gov/rest/json/cves/1.0?keyword=<keyword>
    """
    try:
        base = 'https://services.nvd.nist.gov/rest/json/cves/1.0'
        params = {'keyword': keyword, 'resultsPerPage': max_results}
        r = requests.get(base, params=params, timeout=12)
        if r.status_code == 200:
            data = r.json()
            out = []
            for item in data.get('result', {}).get('CVE_Items', [])[:max_results]:
                meta = item.get('cve', {}).get('CVE_data_meta', {})
                cve_id = meta.get('ID')
                descs = item.get('cve', {}).get('description', {}).get('description_data', [])
                desc = descs[0].get('value') if descs else ''
                cvss = None
                impact = item.get('impact', {})
                if 'baseMetricV3' in impact:
                    cvss = impact['baseMetricV3'].get('cvssV3', {}).get('baseScore')
                elif 'baseMetricV2' in impact:
                    cvss = impact['baseMetricV2'].get('cvssV2', {}).get('baseScore')
                out.append({'id': cve_id, 'description': desc, 'score': cvss})
            return out
        else:
            return []
    except Exception:
        return []


# ----------------------------- Reporting -----------------------------


def generate_report(parsed: Dict[str, Any], target: str, scan_cmd: List[str], start_time: datetime, end_time: datetime, query_cve: bool = False) -> Dict[str, Any]:
    report = {
        'target': target,
        'scan_cmd': ' '.join(scan_cmd),
        'start_time': start_time.isoformat(),
        'end_time': end_time.isoformat(),
        'hosts': []
    }
    for host in parsed.get('hosts', []):
        h = {
            'addresses': host.get('addresses', []),
            'hostname': host.get('hostname'),
            'status': host.get('status'),
            'ports': []
        }
        for p in host.get('ports', []):
            svc = p.get('service', {})
            suggestion = suggest_attacks_for_service(svc.get('name'), p.get('port'), svc.get('version'))
            cves = []
            if query_cve and svc.get('name'):
                keyword = f"{svc.get('name')} {svc.get('product') or ''} {svc.get('version') or ''}".strip()
                if keyword:
                    cves = query_nvd_for_keyword(keyword)
            h['ports'].append({
                'port': p.get('port'),
                'protocol': p.get('protocol'),
                'state': p.get('state'),
                'service': svc,
                'analysis': suggestion,
                'cves': cves
            })
        report['hosts'].append(h)
    return report


def save_report(report: Dict[str, Any], filename: str) -> None:
    ext = os.path.splitext(filename)[1].lower()
    if ext == '.json' or ext == '':
        with open(filename if filename.endswith('.json') else filename + '.json', 'w') as f:
            json.dump(report, f, indent=2)
    elif ext == '.md':
        md = render_report_markdown(report)
        with open(filename, 'w') as f:
            f.write(md)
    elif ext == '.html':
        md = render_report_markdown(report)
        # simple HTML wrapper
        html = f"""<html><head><meta charset=\"utf-8\"><title>Scan Report</title></head><body><pre>{md}</pre></body></html>"""
        with open(filename, 'w') as f:
            f.write(html)
    else:
        with open(filename + '.json', 'w') as f:
            json.dump(report, f, indent=2)


def render_report_markdown(report: Dict[str, Any]) -> str:
    lines = []
    lines.append(f"# Nmap Recon Report for {report.get('target')}")
    lines.append(f"- Scan command: `{report.get('scan_cmd')}`")
    lines.append(f"- Start: {report.get('start_time')}")
    lines.append(f"- End: {report.get('end_time')}")
    lines.append('\n')
    for h in report.get('hosts', []):
        lines.append(f"## Host: {', '.join([a['addr'] for a in h.get('addresses', [])])}")
        lines.append(f"- Hostname: {h.get('hostname')}")
        lines.append(f"- Status: {h.get('status')}")
        lines.append('\n')
        lines.append('| Port | Proto | State | Service | Version | Suggested Attacks |')
        lines.append('|---|---:|---|---|---|---|')
        for p in h.get('ports', []):
            svc = p.get('service', {})
            attacks = ', '.join(p.get('analysis', {}).get('attacks', []))
            version = svc.get('version') or svc.get('product') or ''
            lines.append(f"| {p.get('port')} | {p.get('protocol')} | {p.get('state')} | {svc.get('name') or ''} | {version} | {attacks} |")
        lines.append('\n')
    return '\n'.join(lines)


# ----------------------------- UI / Main Loop -----------------------------


def main_menu():
    console.print(Panel("[bold cyan]Interactive Nmap Recon Assistant[/bold cyan]\nChoose scan options and generate analysis reports."))

    target = Prompt.ask("Enter target (IP or domain)")
    while not is_valid_ip_or_domain(target):
        console.print("[red]Invalid IP or domain. Try again.[/red]")
        target = Prompt.ask("Enter target (IP or domain)")

    options = {
        'fast': False,
        'full': False,
        'service': False,
        'os': False,
        'vuln_scripts': False,
        'custom_cmd': None
    }

    console.print('\n[bold]Select scan types (toggle):[/bold]')
    if Confirm.ask('Fast scan (common ports, -F)?'):
        options['fast'] = True
    if Confirm.ask('Full port scan (1-65535)?'):
        options['full'] = True
    if Confirm.ask('Service version detection (-sV)?'):
        options['service'] = True
    if Confirm.ask('OS detection (-O)? (requires root)'):
        options['os'] = True
    if Confirm.ask('Vulnerability NSE scripts (--script vuln)?'):
        options['vuln_scripts'] = True
    if Confirm.ask('Enter a custom nmap command/flags?'):
        custom = Prompt.ask('Custom Nmap flags (e.g., -sS -A --script=safe)')
        options['custom_cmd'] = custom

    # allow combined scans
    console.print('\nSelected options:')
    for k, v in options.items():
        if v:
            console.print(f" - {k}: {v}")

    # ask about CVE querying
    query_cve = Confirm.ask('Attempt to query NVD for CVEs (best-effort, may be rate-limited)?')

    # output file
    save_report_opt = Confirm.ask('Save report to file?')
    report_filename = None
    if save_report_opt:
        report_filename = Prompt.ask('Filename (extension .json, .md, .html). Example: report.md')

    # loop to allow reruns
    while True:
        # prepare temp xml file
        tmpf = tempfile.NamedTemporaryFile(delete=False, suffix='.xml')
        tmpf.close()
        output_xml = tmpf.name
        cmd = build_nmap_command(target, options, output_xml)

        console.print(Panel(f"[green]Running:[/green] {' '.join(cmd)}"))
        start_time = datetime.utcnow()

        # show progress spinner while subprocess runs
        with Progress(SpinnerColumn(), TextColumn("{task.description}"), BarColumn(), TimeElapsedColumn()) as progress:
            task = progress.add_task("Nmap scan in progress...", start=False)
            progress.start_task(task)

            try:
                completed = run_subprocess(cmd)
            except KeyboardInterrupt:
                console.print('[red]Scan aborted by user.[/red]')
                if os.path.exists(output_xml):
                    os.remove(output_xml)
                return

        end_time = datetime.utcnow()

        if completed.returncode != 0:
            console.print(Panel(f"[red]Nmap exited with code {completed.returncode}. Error:\n{completed.stderr}"))
            if Confirm.ask('Try a different scan or change options?'):
                # let user tweak options
                if Confirm.ask('Change custom flags?'):
                    custom = Prompt.ask('Custom Nmap flags (e.g., -sS -A --script=safe)')
                    options['custom_cmd'] = custom
                if Confirm.ask('Toggle full port scan?'):
                    options['full'] = not options['full']
                if Confirm.ask('Toggle service detection?'):
                    options['service'] = not options['service']
                continue
            else:
                break

        # parse results
        try:
            parsed = parse_nmap_xml(output_xml)
        except Exception as e:
            console.print(f"[red]Failed to parse Nmap XML: {e}[/red]")
            parsed = {'hosts': []}

        report = generate_report(parsed, target, cmd, start_time, end_time, query_cve=query_cve)

        # display
        console.rule('[bold]Scan Analysis[/bold]')
        for h in report.get('hosts', []):
            t = Table(title=f"Host: {', '.join([a['addr'] for a in h.get('addresses', [])])}")
            t.add_column('Port', style='cyan', justify='right')
            t.add_column('Proto', style='magenta')
            t.add_column('State', style='green')
            t.add_column('Service', style='yellow')
            t.add_column('Version', style='white')
            t.add_column('Suggested Attacks', style='red')
            for p in h.get('ports', []):
                svc = p.get('service', {})
                ver = svc.get('version') or svc.get('product') or ''
                attacks = ', '.join(p.get('analysis', {}).get('attacks', []))
                t.add_row(str(p.get('port')), p.get('protocol'), p.get('state'), svc.get('name') or '', ver, attacks)
            console.print(t)
            # show CVEs if present
            for p in h.get('ports', []):
                if p.get('cves'):
                    console.print(f"[bold]CVEs for {p.get('service', {}).get('name')}:{p.get('port')}")
                    for c in p.get('cves'):
                        console.print(f" - {c.get('id')} (score: {c.get('score')}) - {c.get('description')[:200]}...")

        # save report if requested
        if save_report_opt and report_filename:
            try:
                save_report(report, report_filename)
                console.print(f"[green]Report saved to {report_filename}[/green]")
            except Exception as e:
                console.print(f"[red]Failed to save report: {e}[/red]")

        # cleanup xml
        if os.path.exists(output_xml):
            os.remove(output_xml)

        # ask to rerun or change options
        if Confirm.ask('Run another scan with different options on the same target?'):
            # change options interactively
            if Confirm.ask('Toggle fast scan?'):
                options['fast'] = not options['fast']
            if Confirm.ask('Toggle full port scan?'):
                options['full'] = not options['full']
            if Confirm.ask('Toggle service detection?'):
                options['service'] = not options['service']
            if Confirm.ask('Toggle OS detection?'):
                options['os'] = not options['os']
            if Confirm.ask('Toggle NSE vuln scripts?'):
                options['vuln_scripts'] = not options['vuln_scripts']
            if Confirm.ask('Change custom flags?'):
                options['custom_cmd'] = Prompt.ask('Custom Nmap flags (e.g., -sS -A --script=safe)')
            continue
        else:
            console.print('[bold green]Finished. Thank you![/bold green]')
            break


if __name__ == '__main__':
    try:
        main_menu()
    except Exception as e:
        console.print(f"[red]Fatal error: {e}[/red]")
        raise
