# Test Commands (only the tests we ran)

> Run the monitor commands on the **Raspberry Pi** and run the test commands from the **attacker/client** machine (MacBook). Replace `<PI-IP>` with your Pi's IP.

---

## Monitor on Raspberry Pi
```bash
# Monitor short alert format
tail -f /var/log/suricata/fast.log

# Monitor detailed JSON events
tail -f /var/log/suricata/eve.json | jq .
```

---

## Tests (commands we ran)

### 1) Nmap SYN scan — single port (SSH)
```bash
nmap -sS <PI-IP>
```
**Expected:**  
- `fast.log` shows custom SSH alert (sid:1000100) or ET SCAN if default rules match.  

---

### 3) Nmap Aggressive 
```bash
nmap -A <PI-IP>
```
**Expected:**  
- More verbose detection (OS/service detection) and more rule hits from default ruleset.  

---

### 4) SSH attempt (custom rule)
```bash
ssh pi@<PI-IP>
# Press Ctrl+C at password prompt if not testing auth

---

### 5) Suspicious port 4444 (custom rule)
```bash
nc -vz <PI-IP> 4444
```
**Expected:**  
- `fast.log` shows: `Custom Alert: Suspicious port 4444 traffic` (sid:1000101).  

> Note: this may be triggered indirectly by `nmap -sS -p-` if 4444 is in the scanned port list.

---


## Quick notes
- For reproducibility, run the Pi monitors first, then execute each test from the attacker machine one at a time and capture screenshots of both the attacker terminal and the Pi `fast.log` / `eve.json` output.
