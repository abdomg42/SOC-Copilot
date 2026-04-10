# Port Scan / Network Reconnaissance — Response Runbook

## Overview
Port scanning is typically the first phase of an attack. An attacker maps the network to discover open ports, running services, and potential vulnerabilities. While not an attack in itself, a port scan is a strong indicator of imminent attack preparation.

## Detection Criteria
- Wazuh rule IDs: 40111, 40112 (Nmap), 1002, 1003
- Alert level: >= 6
- Trigger: > 50 unique ports scanned within 60 seconds from the same source IP
- Tools commonly detected: Nmap, Masscan, Zmap, Unicornscan

## MITRE ATT&CK Mapping
- Tactic: Discovery (TA0007)
- Technique: T1046 — Network Service Scanning
- Related: T1595.001 — Active Scanning: Scanning IP Blocks

## Severity Assessment
- HIGH: Scan targeting internal network ranges from external IP, followed by connection attempts
- MEDIUM: Full port scan of a single host from external IP, no follow-up activity
- LOW: Partial scan (< 100 ports) from known scanner (Shodan, Censys)
- INFO: Internal host scanning — may be legitimate IT inventory

## Investigation Steps

### Step 1 — Characterize the scan (2 min)
Determine scan type from packet analysis or logs:
- SYN scan (stealthy): only SYN packets, no completion
- Connect scan: full TCP handshake attempts
- UDP scan: slower, targets UDP services
- Version scan (-sV): attacker wants service version info → more targeted

### Step 2 — Identify what was discovered (3 min)
Check which ports were actually open/responding to the scan:
ss -tlnp   # current open TCP ports
ss -ulnp   # current open UDP ports
netstat -an | grep ESTABLISHED | grep <SOURCE_IP>  # active connections from attacker

### Step 3 — Correlate with subsequent activity (3 min)
A scan is usually followed by exploitation attempts. Check for:
grep <SOURCE_IP> /var/log/auth.log        # SSH attempts
grep <SOURCE_IP> /var/log/apache2/access.log  # HTTP/HTTPS attempts
Check Wazuh for alerts from same IP in next 30 minutes

### Step 4 — Identify scan tool used (1 min)
Nmap fingerprint in logs: "Nmap: SYN Stealth Scan"
Masscan: extremely high scan rate (10,000+ ports/sec)
Manual tool: slower, irregular timing

## Remediation Actions

### Immediate (within 15 minutes)
1. Block the scanning IP at the firewall perimeter:
   iptables -A INPUT -s <SOURCE_IP> -j DROP
2. If scan came from internal network: investigate the source host for compromise
3. Alert the team — a scan means an attack attempt is likely imminent

### Short-term (within 2 hours)
4. Audit and reduce the attack surface:
   - List all open ports: nmap -sV localhost
   - Close or restrict services that don't need internet exposure
   - Move admin services (SSH, RDP) behind VPN
5. Add rate limiting on the firewall for new connection attempts
6. Enable port knocking for sensitive services if not already in place

### Long-term (within 48 hours)
7. Deploy a honeypot to detect future reconnaissance attempts
8. Review firewall rules — principle of least exposure
9. Implement network segmentation to limit lateral movement after a scan
10. Configure IDS/IPS rules to auto-block IPs performing scans > threshold

## Indicators of Compromise (IOCs)
- Source IP performing the scan
- Scan time window
- Target ports list (indicates attacker intent if targeting specific ports like 3306/MySQL, 5432/PostgreSQL)
- User-agent or tool signature if HTTP scan

## Notes
A scan from a Shodan/Censys/Censys IP is usually automated internet-wide scanning, not targeted. Verify the IP against known scanner databases before escalating.
