# Compliance Auditor

A modular, extensible compliance validation framework designed to rapidly verify vulnerability scanner findings (Nessus, OpenVAS) during PCI DSS and internal penetration testing engagements.

Instead of maintaining dozens of standalone scripts, Compliance Auditor uses a unified module system to test large lists of `IP:Port` targets and consolidates the results into a single, QSA-ready CSV report.

## Current Modules

### 1. TLS Module (`-m tls`)
Validates cryptographic compliance using Nmap (`ssl-enum-ciphers`) with an automatic fallback to `sslscan` for edge cases (like WAFs or load balancers).
- **Checks For:** Deprecated protocols (SSLv3, TLS 1.0, TLS 1.1) and Weak Ciphers (SWEET32, RC4, DES, IDEA, NULL, Export).

### 2. RDP Module (`-m rdp`)
Validates Remote Desktop Protocol security configurations.
- **Checks For:** NLA Enforcement vs. Support (MitM vulnerabilities), Weak "Low" Encryption Levels, and NTLM Information Disclosure (leaking domains/OS versions).

### 3. SSH Module (`-m ssh`)
Validates SSH cryptographic configurations using Nmap (`ssh2-enum-algos`).
- **Checks For:** Weak CBC Mode Ciphers, Arcfour Ciphers, Weak MAC algorithms (MD5, SHA1, 96-bit), and Weak Key Exchange (KEX) algorithms (Group 1, SHA1).

### 4. SMB Module (`-m smb`)
Validates SMB security configurations using Nmap (`smb2-security-mode`, `smb-security-mode`).
- **Checks For:** SMB Message Signing Not Required (leads to NTLM relay attacks).

### 5. HTTP Headers Module (`-m http`)
Validates web server security headers. Uses `curl` as the primary engine (robust against WAFs) with an automatic fallback to Python `urllib`.
- **Checks For:** Cleartext HTTP (not HTTPS), Missing HSTS Header, Missing X-Frame-Options (Clickjacking), and Missing X-Content-Type-Options.

### 6. Run All Modules (`-m all`)
Runs all available modules against the provided target list.

## Installation

### Prerequisites
The framework relies on native Linux testing tools. Ensure they are installed:
```bash
sudo apt-get update
sudo apt-get install -y nmap sslscan curl python3
```

### Setup
```bash
git clone https://github.com/yourusername/compliance-auditor.git
cd compliance-auditor
chmod +x auditor.py
```

## Usage

The script uses `argparse` for easy CLI execution. Provide the module (`-m`), the target list (`-t`), and the desired output CSV (`-o`).

Create a target file (e.g., `targets.txt`) with one `IP:Port` per line:
```text
10.50.1.15:443
10.50.1.22:3389
192.168.100.5:22
```

### Example: Running a Specific Module
```bash
./auditor.py -m ssh -t targets.txt -o ssh_remediation_report.csv
```

### Example: Running All Checks
```bash
./auditor.py -m all -t targets.txt -o full_remediation_report.csv
```

### Expected Output Structure (CSV)
The unified CSV structure makes it easy to merge results across modules.

| IP | Port | Check Type | Vulnerable | Vulnerability Details |
|---|---|---|---|---|
| 10.50.1.15 | 443 | TLS Check | Yes | TLSv1.0 Enabled \| TLSv1.1 Enabled |
| 10.50.1.22 | 3389 | RDP Check | Yes | NLA Not Enforced (MitM Possible) |
| 192.168.100.5 | 22 | SSH Check | Yes | CBC Mode Ciphers Enabled \| Weak MAC Algorithms Enabled |
| 192.168.100.5 | 80 | HTTP Check | Yes | Cleartext HTTP (Not HTTPS) \| Missing X-Frame-Options (Clickjacking) |

## Extending the Framework
Adding a new check is as simple as defining a new `check_function(ip, port)` that returns `(Check_Name, is_vulnerable_boolean, Details)` and adding it to the `argparse` choices in the main block.
