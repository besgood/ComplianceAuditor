#!/usr/bin/env python3
import sys
import subprocess
import csv
import xml.etree.ElementTree as ET
import re
import argparse
import concurrent.futures
import urllib.request
import ssl

# --- Common Utilities ---

def parse_targets(targets_file):
    targets = []
    try:
        with open(targets_file, "r") as f:
            for line in f:
                line = line.strip()
                if line and ":" in line:
                    ip, port = line.split(":", 1)
                    targets.append((ip.strip(), port.strip()))
        return targets
    except Exception as e:
        print(f"[!] Error reading {targets_file}: {e}")
        sys.exit(1)

def write_csv(output_file, results):
    try:
        with open(output_file, "w", newline="") as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(["IP", "Port", "Check Type", "Vulnerable", "Vulnerability Details"])
            writer.writerows(results)
        print(f"[*] Success! Results saved to {output_file}")
    except Exception as e:
        print(f"[!] Error writing to {output_file}: {e}")

# --- TLS Module ---

weak_cipher_patterns = {
    r"3DES": "SWEET32 (3DES)", r"RC4": "RC4", r"DES": "DES",
    r"IDEA": "IDEA", r"NULL": "NULL Cipher", r"anon": "Anonymous Cipher", r"EXP": "Export Cipher"
}

def run_sslscan(ip, port):
    cmd = ["sslscan", "--no-failed", f"{ip}:{port}"]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        output = proc.stdout
        if "Connection refused" in output or "Could not open connection" in output:
            return "Error", "Connection refused/failed (sslscan)", False
        vulns, ciphers_found, proto_vulns = [], set(), set()
        has_accepted = False
        for line in output.split("\n"):
            line = line.strip()
            if line.startswith("Accepted"):
                has_accepted = True
                parts = line.split()
                if len(parts) >= 2:
                    proto = parts[1]
                    if proto in ["SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1", "TLSv1"]:
                        if proto == "TLSv1": proto = "TLSv1.0"
                        proto_vulns.add(f"{proto} Enabled")
                    cipher_name = parts[-1]
                    for pat, name in weak_cipher_patterns.items():
                        if re.search(pat, cipher_name, re.IGNORECASE):
                            ciphers_found.add(name)
        if not has_accepted: return "Error", "No SSL/TLS response (sslscan)", False
        vulns.extend(sorted(proto_vulns))
        if ciphers_found: vulns.append("Weak Ciphers: " + ", ".join(sorted(ciphers_found)))
        if vulns: return "Yes", " | ".join(vulns), True
        return "No", "Secure configuration (No weak TLS/ciphers found)", True
    except subprocess.TimeoutExpired: return "Error", "Scan timed out (sslscan)", False
    except Exception as e: return "Error", f"sslscan failed: {str(e)}", False

def run_tls_nmap(ip, port):
    cmd = ["nmap", "-Pn", "-p", port, "--script", "ssl-enum-ciphers", ip, "-oX", "-"]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        vulns = []
        try:
            tree = ET.fromstring(proc.stdout)
            script_output = None
            for script in tree.findall(".//script"):
                if script.get("id") == "ssl-enum-ciphers": script_output = script.get("output"); break
            if script_output:
                for proto in ["SSLv3", "TLSv1.0", "TLSv1.1"]:
                    if f"{proto}:" in script_output: vulns.append(f"{proto} Enabled")
                ciphers_found = set()
                for line in script_output.split("\n"):
                    line = line.strip()
                    if line.startswith("TLS_") or line.startswith("SSL_"):
                        cipher_name = line.split()[0]
                        for pat, name in weak_cipher_patterns.items():
                            if re.search(pat, cipher_name, re.IGNORECASE): ciphers_found.add(name)
                if ciphers_found: vulns.append("Weak Ciphers: " + ", ".join(sorted(ciphers_found)))
                if vulns: return "Yes", " | ".join(vulns), True
                return "No", "Secure configuration (No weak TLS/ciphers found)", True
            return "Error", "No script output", False
        except ET.ParseError: return "Error", "Failed to parse Nmap XML", False
    except Exception as e: return "Error", f"Nmap failed: {str(e)}", False

def check_tls(ip, port):
    is_vuln, details, success = run_tls_nmap(ip, port)
    if not success:
        is_vuln, details, sslscan_success = run_sslscan(ip, port)
        if not sslscan_success and is_vuln != "Error": is_vuln = "Error"
    return "TLS Check", is_vuln, details

# --- RDP Module ---

def check_rdp(ip, port):
    cmd = ["nmap", "-Pn", "-p", port, "--script", "rdp-enum-encryption,rdp-ntlm-info", ip, "-oX", "-"]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        vulns = []
        try:
            tree = ET.fromstring(proc.stdout)
            enum_output, ntlm_output = None, None
            for script in tree.findall(".//script"):
                if script.get("id") == "rdp-enum-encryption": enum_output = script.get("output")
                elif script.get("id") == "rdp-ntlm-info": ntlm_output = script.get("output")
            if enum_output:
                native_rdp = re.search(r"Native RDP:\s*SUCCESS", enum_output, re.IGNORECASE)
                rdstls = re.search(r"RDSTLS:\s*SUCCESS", enum_output, re.IGNORECASE)
                credssp = re.search(r"CredSSP \(NLA\):\s*SUCCESS", enum_output, re.IGNORECASE)
                if not credssp: vulns.append("NLA Not Supported")
                elif native_rdp or rdstls: vulns.append("NLA Not Enforced (MitM Possible)")
                if re.search(r"RDP Encryption level:\s*Low", enum_output, re.IGNORECASE):
                    vulns.append("Weak RDP Encryption (Low)")
            if ntlm_output: vulns.append("NTLM Info Disclosure")
            if vulns: return "RDP Check", "Yes", " | ".join(vulns)
            elif enum_output: return "RDP Check", "No", "Secure configuration (NLA Enforced, Strong Encryption)"
            return "RDP Check", "Error", "No RDP encryption info found"
        except ET.ParseError: return "RDP Check", "Error", "Failed to parse Nmap XML"
    except Exception as e: return "RDP Check", "Error", str(e)

# --- SSH Module ---
def check_ssh(ip, port):
    cmd = ["nmap", "-Pn", "-p", port, "--script", "ssh2-enum-algos", ip, "-oX", "-"]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        vulns = []
        try:
            tree = ET.fromstring(proc.stdout)
            script_output = None
            for script in tree.findall(".//script"):
                if script.get("id") == "ssh2-enum-algos": script_output = script.get("output")
            if script_output:
                if re.search(r"-cbc\b", script_output): vulns.append("CBC Mode Ciphers Enabled")
                if re.search(r"arcfour", script_output): vulns.append("Arcfour Ciphers Enabled")
                if re.search(r"-md5\b|-sha1\b|-96\b", script_output): vulns.append("Weak MAC Algorithms Enabled")
                if re.search(r"group1-sha1|group-exchange-sha1", script_output): vulns.append("Weak Key Exchange (KEX) Enabled")

                if vulns: return "SSH Check", "Yes", " | ".join(vulns)
                return "SSH Check", "No", "Secure configuration (Strong Algos Only)"
            return "SSH Check", "Error", "No SSH algo info found"
        except ET.ParseError: return "SSH Check", "Error", "Failed to parse Nmap XML"
    except Exception as e: return "SSH Check", "Error", str(e)

# --- SMB Module ---
def check_smb(ip, port):
    cmd = ["nmap", "-Pn", "-p", port, "--script", "smb2-security-mode,smb-security-mode", ip, "-oX", "-"]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        try:
            tree = ET.fromstring(proc.stdout)
            signing_req = False
            found_smb = False
            for script in tree.findall(".//script"):
                out = script.get("output")
                if out:
                    found_smb = True
                    if "Message signing enabled and required" in out or "required: true" in out.lower():
                        signing_req = True
            if found_smb:
                if not signing_req: return "SMB Check", "Yes", "SMB Signing Not Required"
                return "SMB Check", "No", "SMB Signing Required"
            return "SMB Check", "Error", "No SMB security mode info found"
        except ET.ParseError: return "SMB Check", "Error", "Failed to parse Nmap XML"
    except Exception as e: return "SMB Check", "Error", str(e)

# --- HTTP Module (Cross-Validated curl + urllib) ---
def run_http_urllib(ip, port, is_https):
    protocol = "https" if is_https else "http"
    url = f"{protocol}://{ip}:{port}"
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        req = urllib.request.Request(url, method="HEAD")
        with urllib.request.urlopen(req, context=ctx, timeout=10) as response:
            return {k.lower(): v.lower() for k, v in response.headers.items()}
    except urllib.error.HTTPError as e:
        return {k.lower(): v.lower() for k, v in e.headers.items()}
    except:
        return None

def check_http(ip, port):
    vulns = []
    is_https = False
    headers = {}

    # 1. Primary check using curl (robust against WAFs)
    cmd = ["curl", "-s", "-I", "-k", "-m", "10", f"https://{ip}:{port}"]
    proc = subprocess.run(cmd, capture_output=True, text=True)

    if proc.stdout.startswith("HTTP"):
        is_https = True
        for line in proc.stdout.split("\n"):
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip().lower()] = v.strip().lower()
    else:
        # Try HTTP
        cmd = ["curl", "-s", "-I", "-m", "10", f"http://{ip}:{port}"]
        proc = subprocess.run(cmd, capture_output=True, text=True)
        if proc.stdout.startswith("HTTP"):
            for line in proc.stdout.split("\n"):
                if ":" in line:
                    k, v = line.split(":", 1)
                    headers[k.strip().lower()] = v.strip().lower()

    # 2. Fallback check using urllib if curl returned nothing
    if not headers:
        headers = run_http_urllib(ip, port, True)
        if headers: is_https = True
        else:
            headers = run_http_urllib(ip, port, False)

    if not headers:
        return "HTTP Check", "Error", "No HTTP/HTTPS response (curl & urllib failed)"

    # Evaluate findings
    if not is_https: vulns.append("Cleartext HTTP (Not HTTPS)")
    else:
        if "strict-transport-security" not in headers: vulns.append("Missing HSTS Header")

    if "x-frame-options" not in headers: vulns.append("Missing X-Frame-Options (Clickjacking)")
    if "x-content-type-options" not in headers: vulns.append("Missing X-Content-Type-Options")

    if vulns: return "HTTP Check", "Yes", " | ".join(vulns)
    return "HTTP Check", "No", "Secure HTTP Headers Present"


# --- Main Orchestrator ---

def main():
    parser = argparse.ArgumentParser(description="Compliance Auditor - Modular Vulnerability Validator")
    parser.add_argument("-m", "--module", choices=["tls", "rdp", "ssh", "smb", "http", "all"], required=True, help="Module to run")
    parser.add_argument("-t", "--targets", required=True, help="File containing ip:port targets")
    parser.add_argument("-o", "--output", required=True, help="Output CSV file")

    args = parser.parse_args()

    targets = parse_targets(args.targets)
    print(f"[*] Loaded {len(targets)} targets. Starting {args.module.upper()} validation scans...")

    results = []

    def scan_target(target):
        ip, port = target
        out = []
        if args.module in ["tls", "all"]: out.append([ip, port] + list(check_tls(ip, port)))
        if args.module in ["rdp", "all"]: out.append([ip, port] + list(check_rdp(ip, port)))
        if args.module in ["ssh", "all"]: out.append([ip, port] + list(check_ssh(ip, port)))
        if args.module in ["smb", "all"]: out.append([ip, port] + list(check_smb(ip, port)))
        if args.module in ["http", "all"]: out.append([ip, port] + list(check_http(ip, port)))
        return out

    print(f"[*] Launching threaded scans (Max 10 concurrent)...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(scan_target, t) for t in targets]
        for future in concurrent.futures.as_completed(futures):
            try:
                res_list = future.result()
                if res_list:
                    for res in res_list:
                        results.append(res)
            except Exception as exc:
                print(f"[!] Target generated an exception: {exc}")

    print(f"[*] Scans complete. Writing results to {args.output}...")
    write_csv(args.output, results)

if __name__ == "__main__":
    main()
