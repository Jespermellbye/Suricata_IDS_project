# Intrusion Detection Project (Raspberry Pi + Suricata)

Suricata + Raspberry Pi Screenshot

## Overview

This project demonstrates how to use a **Raspberry Pi** as a lightweight **Intrusion Detection System (IDS)**.  
The IDS monitors traffic, applies both **default Suricata rules** and **custom rules**, and logs suspicious activity.

The goal was to detect simulated anomalies such as port scans, SSH attempts, and traffic to unusual ports.

---

## Setup

### Hardware
- Raspberry Pi 5 
- SD card 32GB
- Ethernet connection
- MacBook Pro (attacker/test client)

### Software
- Raspberry Pi OS Lite (Bookworm)
- Suricata 6.x
- nmap, netcat (for testing)
- jq (for JSON log parsing)

### Suricata Configuration
- **HOME_NET:** `192.168.0.0/24`
- **default-rule-path:** `/var/lib/suricata/rules`
- **rule-files:**
  ```yaml
  rule-files:
    - suricata.rules
    - custom.rules
  ```
- **outputs:**
  ```yaml
  outputs:
    - fast:
        enabled: yes
        filename: fast.log
        append: yes
  ```

📷 *Screenshot: systemctl status suricata*  
📷 *Screenshot: suricata -T showing both suricata.rules and custom.rules loaded*  

---

## Custom Rules

Two simple custom rules were created for controlled testing:

```text
alert tcp any any -> any 22 (msg:"Custom Alert: SSH connection attempt"; sid:1000100; rev:1;)
alert tcp any any -> any 4444 (msg:"Custom Alert: Suspicious port 4444 traffic"; sid:1000101; rev:1;)
```

📷 *Screenshot: custom.rules in VS Code*  

---

## Simulated Traffic

### Port scan (default rules should trigger)
On attacker:
```bash
nmap -sS <PI-IP>
nmap -A <PI-IP>
```
 *Screenshot: fast.log with ET SCAN alerts*

---

### SSH attempt (custom rule)
On attacker:
```bash
ssh pi@<PI-IP>
```
 *Screenshot: fast.log with "Custom Alert: SSH connection attempt"*

---

### Suspicious port 4444 (custom rule)
On attacker:
```bash
nc -v <PI-IP> 4444
```
 *Screenshot: fast.log with "Custom Alert: Suspicious port 4444 traffic"*

---

### ICMP ping (flow only, no alert)
On attacker:
```bash
ping -c 4 <PI-IP>
```
 *Screenshot: eve.json with flow event (ICMP), fast.log unchanged*

---

## Analysis

### Alerts Observed
| Test             | Expected | Observed |
|------------------|----------|----------|
| Nmap SYN scan    | ET SCAN alert | ✅ |
| Nmap aggressive  | Multiple alerts | ✅ |
| SSH attempt      | Custom alert | ✅ |
| Port 4444 access | Custom alert | ✅ |
| ICMP ping        | Flow only | ✅ |

 *Screenshot: Combined fast.log showing ET SCAN + custom alerts*  

---

## Key Learnings

- Suricata distinguishes between **flows** (all traffic) and **alerts** (rule matches).  
- Custom rules can be easily added for targeted detection.  
- IDS mode is safe for testing because it only logs, it does not block traffic.  
- YAML configuration must be correct (`default-rule-path`, indentation).  

---

## IDS vs IPS

Suricata also supports **IPS mode** (Intrusion Prevention System) where traffic can be blocked.  
For this project, IPS was **not enabled** because:
1. Inline IPS could disrupt legitimate traffic.
2. Raspberry Pi has limited performance overhead.

Instead, focus was kept on **IDS mode** for monitoring and alerting.

---

## Future Work

- Integrate Suricata logs into a SIEM (e.g., ELK or Wazuh).  
- Build dashboards for visualization.  
- Experiment with IPS in a controlled lab environment.  

---

## Conclusion

- Raspberry Pi can act as a **low-cost IDS** using Suricata.  
- Detected both **realistic scans** (nmap) and **custom test rules**.  
- Hands-on demonstration of **network monitoring and intrusion detection**.  

## Use of AI Assistance
During this project, ChatGPT was used as a supportive tool. The AI was primarily applied to:
- Provide step-by-step guidance for configuring Suricata on Raspberry Pi.
- Help create and refine custom rules for SSH and suspicious port traffic.
- Generate automation scripts (e.g., setting up rule files, structuring the GitHub repository).
- Draft and format the initial version of the README and documentation structure.

All testing, verification, and analysis of alerts were performed manually by me on the Raspberry Pi environment.
The AI was not used to run the IDS or simulate traffic but rather to accelerate learning, scripting, and documentation.
