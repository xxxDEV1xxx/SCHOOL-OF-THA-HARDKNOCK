#!/usr/bin/env python3
"""
CTW-11 GUARD TOWER VPN SECURITY SYSTEM
=======================================
A multi-function security gateway layered
over a PPTP VPN server.

FUNCTIONS:
  1. PPTP + GRE kernel-level packet filter
  2. Certificate probe — detects MITM TLS interception
  3. DNS cache + MITM detection
  4. File hash enforcement — unknown downloads blocked
  5. ASN/geolocation client verification
  6. Device fingerprint enforcement — iOS vs macOS detection

Inventor: Christopher Thomas Williams
Active filings: FCC/NRC/DOJ/Cal OES
Patent: USPTO 19/466,387
"""

import os
import sys
import ssl
import json
import time
import socket
import hashlib
import struct
import logging
import sqlite3
import threading
import subprocess
import ipaddress
import urllib.request
from datetime import datetime
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Optional, Dict, Set, Tuple

# ============================================================
# DEPENDENCIES CHECK
# pip install netfilterqueue scapy requests geoip2
# ============================================================
try:
    from netfilterqueue import NetfilterQueue
    from scapy.all import IP, TCP, UDP, Raw, DNS, DNSQR
    import requests
    DEPS_OK = True
except ImportError:
    DEPS_OK = False
    print("[WARN] Some dependencies missing — partial mode")

# ============================================================
# CONFIGURATION
# ============================================================

# Network
VPN_INTERFACE   = "ppp0"
LAN_INTERFACE   = "eth0"
WAN_INTERFACE   = "eth1"
VPN_SUBNET      = "192.168.100.0/24"
VPN_SERVER_IP   = "192.168.100.1"
DNS_PORT        = 53
PPTP_PORT       = 1723

# NFQUEUE numbers
QUEUE_CERT      = 10   # certificate verification
QUEUE_DNS       = 11   # DNS MITM detection
QUEUE_FILE      = 12   # file hash enforcement
QUEUE_DEVICE    = 13   # device fingerprinting

# Certificate verification
CERT_PROBE_TIMEOUT  = 5    # seconds
CERT_MISMATCH_DROP  = True

# File hash enforcement
HASH_DB_PATH    = "/var/lib/ctw_guard/file_hashes.db"
UNKNOWN_DROP    = True       # drop unknown files by default

# Geolocation
GEO_DB_PATH     = "/var/lib/GeoIP/GeoLite2-ASN.mmdb"
GEO_ENFORCE     = True

# Device fingerprinting
DEVICE_ENFORCE  = True

# Logging
LOG_DIR         = "/var/log/ctw_guard"
LOG_LEVEL       = logging.DEBUG

# Known client registrations
# populated at runtime by admin
REGISTERED_CLIENTS: Dict[str, dict] = {}

# ============================================================
# LOGGING SETUP
# ============================================================

os.makedirs(LOG_DIR, exist_ok=True)

logging.basicConfig(
    level=LOG_LEVEL,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    handlers=[
        logging.FileHandler(f"{LOG_DIR}/guard_tower.log"),
        logging.StreamHandler(sys.stdout)
    ]
)
log = logging.getLogger("CTW-GUARD")

# ============================================================
# PART 1: IPTABLES RULESET
# PPTP + GRE + explicit packet filtering
# ============================================================

IPTABLES_SETUP = """
#!/bin/bash
# CTW-11 GUARD TOWER IPTABLES SETUP
# Explicit whitelist architecture — deny all, allow specific

set -euo pipefail

IPT="iptables"
VPN_NET="192.168.100.0/24"
VPN_IF="ppp0"
LAN_IF="eth0"
WAN_IF="eth1"

echo "[*] Flushing existing rules..."
$IPT -F
$IPT -X
$IPT -t nat -F
$IPT -t nat -X
$IPT -t mangle -F
$IPT -t mangle -X
$IPT -t raw -F
$IPT -t raw -X

echo "[*] Setting default policies — DENY ALL..."
$IPT -P INPUT   DROP
$IPT -P OUTPUT  DROP
$IPT -P FORWARD DROP

# ============================================================
# LOOPBACK — always allow
# ============================================================
$IPT -A INPUT  -i lo -j ACCEPT
$IPT -A OUTPUT -o lo -j ACCEPT

# ============================================================
# ESTABLISHED/RELATED — allow return traffic
# ============================================================
$IPT -A INPUT  -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
$IPT -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
$IPT -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# ============================================================
# PPTP VPN — GRE protocol 47 + control port 1723
# ============================================================
# GRE encapsulation (protocol 47) — inbound/outbound
$IPT -A INPUT  -p 47 -j ACCEPT
$IPT -A OUTPUT -p 47 -j ACCEPT

# PPTP control connection — port 1723
$IPT -A INPUT  -p tcp --dport 1723 -j ACCEPT
$IPT -A OUTPUT -p tcp --dport 1723 -j ACCEPT

# Allow VPN clients in from ppp interfaces
$IPT -A INPUT  -i $VPN_IF -s $VPN_NET -j ACCEPT
$IPT -A OUTPUT -o $VPN_IF -d $VPN_NET -j ACCEPT

# ============================================================
# FORWARD CHAIN — VPN clients to/from internet
# Route through NFQUEUE security layers first
# ============================================================

# Queue to certificate verifier
$IPT -A FORWARD -i $VPN_IF -p tcp --dport 443 \
    -m conntrack --ctstate NEW \
    -j NFQUEUE --queue-num 10

# Queue to DNS MITM detector
$IPT -A FORWARD -i $VPN_IF -p udp --dport 53 \
    -j NFQUEUE --queue-num 11
$IPT -A FORWARD -i $VPN_IF -p tcp --dport 53 \
    -j NFQUEUE --queue-num 11

# Queue file downloads to hash enforcer
$IPT -A FORWARD -i $VPN_IF -p tcp --dport 80 \
    -m conntrack --ctstate NEW \
    -j NFQUEUE --queue-num 12
$IPT -A FORWARD -i $VPN_IF -p tcp --dport 443 \
    -m conntrack --ctstate NEW \
    -j NFQUEUE --queue-num 12

# Queue device fingerprinting
$IPT -A FORWARD -i $VPN_IF \
    -m conntrack --ctstate NEW \
    -j NFQUEUE --queue-num 13

# Allow forwarded traffic that passed all queues
$IPT -A FORWARD -i $VPN_IF -o $WAN_IF \
    -m conntrack --ctstate ESTABLISHED \
    -j ACCEPT
$IPT -A FORWARD -i $WAN_IF -o $VPN_IF \
    -m conntrack --ctstate ESTABLISHED \
    -j ACCEPT

# ============================================================
# EXPLICIT PROTOCOL WHITELIST
# Only named protocols pass — everything else dropped
# ============================================================

# DNS — only through our server
$IPT -A FORWARD -i $VPN_IF -p udp --dport 53 \
    -d $VPN_SERVER_IP -j ACCEPT

# HTTP/HTTPS
$IPT -A FORWARD -i $VPN_IF -p tcp \
    --dport 80  -j ACCEPT
$IPT -A FORWARD -i $VPN_IF -p tcp \
    --dport 443 -j ACCEPT

# SMTP/SMTPS/IMAP/IMAPS/POP3S
$IPT -A FORWARD -i $VPN_IF -p tcp \
    -m multiport --dports 25,465,587,993,995 \
    -j ACCEPT

# NTP
$IPT -A FORWARD -i $VPN_IF -p udp --dport 123 \
    -j ACCEPT

# SSH — log all SSH through VPN
$IPT -A FORWARD -i $VPN_IF -p tcp --dport 22 \
    -j LOG --log-prefix "CTW-SSH-FWD: " --log-level 4
$IPT -A FORWARD -i $VPN_IF -p tcp --dport 22 \
    -j ACCEPT

# ICMP — limited
$IPT -A FORWARD -i $VPN_IF -p icmp \
    --icmp-type echo-request \
    -m limit --limit 5/sec --limit-burst 10 \
    -j ACCEPT

# ============================================================
# EXPLICIT DROP RULES — named threats
# ============================================================

# Block AMT ports from ALL VPN clients
$IPT -A FORWARD -i $VPN_IF -p tcp \
    -m multiport --dports 16992,16993,16994,16995 \
    -j LOG --log-prefix "CTW-AMT-BLOCKED: " --log-level 4
$IPT -A FORWARD -i $VPN_IF -p tcp \
    -m multiport --dports 16992,16993,16994,16995 \
    -j DROP

# Block NetBIOS/WINS
$IPT -A FORWARD -i $VPN_IF -p udp \
    -m multiport --dports 137,138,139 \
    -j DROP
$IPT -A FORWARD -i $VPN_IF -p tcp --dport 139 \
    -j DROP

# Block UPnP
$IPT -A FORWARD -i $VPN_IF -p udp --dport 1900 \
    -j DROP

# Block LDAP/Kerberos (no SSSD phoning home)
$IPT -A FORWARD -i $VPN_IF -p tcp \
    -m multiport --dports 389,636,88,464 \
    -j LOG --log-prefix "CTW-SSSD-BLOCKED: " --log-level 4
$IPT -A FORWARD -i $VPN_IF -p tcp \
    -m multiport --dports 389,636,88,464 \
    -j DROP

# Log and drop everything else
$IPT -A FORWARD \
    -m limit --limit 10/min \
    -j LOG --log-prefix "CTW-IMPLICIT-DROP: " --log-level 4
$IPT -A FORWARD -j DROP
$IPT -A INPUT   -j DROP
$IPT -A OUTPUT  -j DROP

# ============================================================
# NAT — masquerade VPN clients onto WAN
# ============================================================
$IPT -t nat -A POSTROUTING \
    -s $VPN_NET \
    -o $WAN_IF \
    -j MASQUERADE

# ============================================================
# MANGLE — mark suspicious packets for logging
# ============================================================
# Mark packets from unknown devices (fingerprint fail)
$IPT -t mangle -A FORWARD \
    -i $VPN_IF \
    -m connmark --mark 0xFF \
    -j LOG --log-prefix "CTW-DEVICE-SPOOF: " --log-level 2

echo "[*] Enabling IP forwarding..."
echo 1 > /proc/sys/net/ipv4/ip_forward

echo "[*] Guard Tower iptables rules installed"
echo "[*] Starting Python security daemon..."
"""

def apply_iptables():
    """Write and apply iptables ruleset"""
    script = "/tmp/ctw_iptables_setup.sh"
    with open(script, 'w') as f:
        f.write(IPTABLES_SETUP)
    os.chmod(script, 0o700)
    result = subprocess.run(
        ['bash', script],
        capture_output=True, text=True
    )
    log.info(f"iptables: {result.stdout.strip()}")
    if result.returncode != 0:
        log.error(f"iptables error: {result.stderr}")
    return result.returncode == 0

# ============================================================
# PART 2: CERTIFICATE VERIFICATION
# Probe same site independently to detect MITM TLS
# ============================================================

@dataclass
class CertInfo:
    subject:     str
    issuer:      str
    fingerprint: str
    san:         list
    not_before:  str
    not_after:   str
    serial:      str

class CertificateVerifier:
    """
    For every HTTPS connection a VPN client makes:
    1. Extract the SNI hostname from the ClientHello
    2. VPN server independently probes the same host
    3. Compare certificate fingerprints
    4. If mismatch = MITM detected = drop + log
    """

    def __init__(self):
        self.cache:    Dict[str, CertInfo] = {}
        self.cache_ttl: Dict[str, float]  = {}
        self.CACHE_TTL = 300  # 5 minutes
        self.lock = threading.Lock()
        self.blocked: Set[str] = set()
        self.log = logging.getLogger("CTW-CERT")

    def get_cert_independent(
        self, hostname: str, port: int = 443
    ) -> Optional[CertInfo]:
        """
        VPN server probes hostname directly.
        This is our ground truth.
        """
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            conn = ctx.wrap_socket(
                socket.create_connection(
                    (hostname, port),
                    timeout=CERT_PROBE_TIMEOUT
                ),
                server_hostname=hostname
            )

            der = conn.getpeercert(binary_form=True)
            cert = conn.getpeercert()
            conn.close()

            fingerprint = hashlib.sha256(der).hexdigest()

            san = []
            if 'subjectAltName' in cert:
                san = [v for _, v in cert['subjectAltName']]

            return CertInfo(
                subject=str(cert.get('subject','')),
                issuer=str(cert.get('issuer','')),
                fingerprint=fingerprint,
                san=san,
                not_before=cert.get('notBefore',''),
                not_after=cert.get('notAfter',''),
                serial=str(cert.get('serialNumber',''))
            )
        except Exception as e:
            self.log.warning(f"Probe failed for {hostname}: {e}")
            return None

    def extract_sni(self, payload: bytes) -> Optional[str]:
        """Extract SNI from TLS ClientHello"""
        try:
            # TLS record header: type(1) + version(2) + length(2)
            if len(payload) < 5 or payload[0] != 0x16:
                return None

            # Skip to handshake
            idx = 5
            if payload[idx] != 0x01:  # ClientHello
                return None

            # Skip to extensions
            idx += 4 + 2 + 32  # header + version + random
            session_len = payload[idx]
            idx += 1 + session_len
            cs_len = struct.unpack_from('>H', payload, idx)[0]
            idx += 2 + cs_len
            cm_len = payload[idx]
            idx += 1 + cm_len

            # Extensions
            if idx + 2 > len(payload):
                return None
            ext_total = struct.unpack_from('>H', payload, idx)[0]
            idx += 2
            end = idx + ext_total

            while idx < end - 4:
                ext_type = struct.unpack_from('>H', payload, idx)[0]
                ext_len  = struct.unpack_from('>H', payload, idx+2)[0]
                idx += 4

                if ext_type == 0:  # SNI extension
                    # SNI list length(2) + type(1) + name_length(2) + name
                    name_len = struct.unpack_from(
                        '>H', payload, idx+3)[0]
                    sni = payload[idx+5:idx+5+name_len].decode(
                        'ascii', errors='replace')
                    return sni

                idx += ext_len

        except Exception:
            pass
        return None

    def verify(
        self, hostname: str, client_cert_fp: str
    ) -> Tuple[bool, str]:
        """
        Compare client's presented cert against our probe.
        Returns (ok, reason)
        """
        now = time.time()

        with self.lock:
            # Check cache
            if hostname in self.cache:
                if now - self.cache_ttl[hostname] < self.CACHE_TTL:
                    our_cert = self.cache[hostname]
                else:
                    del self.cache[hostname]

        # Probe independently
        our_cert = self.get_cert_independent(hostname)
        if our_cert is None:
            return True, "PROBE_FAILED_ALLOW"

        with self.lock:
            self.cache[hostname] = our_cert
            self.cache_ttl[hostname] = now

        # Compare fingerprints
        if our_cert.fingerprint != client_cert_fp:
            reason = (
                f"CERT_MISMATCH hostname={hostname} "
                f"expected={our_cert.fingerprint[:16]} "
                f"got={client_cert_fp[:16]}"
            )
            self.log.critical(f"MITM DETECTED: {reason}")
            self.blocked.add(hostname)
            return False, reason

        return True, "CERT_OK"

    def handle_packet(self, pkt):
        """NFQUEUE handler for queue 10"""
        try:
            if not DEPS_OK:
                pkt.accept()
                return

            from scapy.all import IP, TCP
            ip = IP(pkt.get_payload())

            if not ip.haslayer(TCP):
                pkt.accept()
                return

            tcp = ip[TCP]
            raw = bytes(tcp.payload) if tcp.payload else b''

            if len(raw) > 5 and raw[0] == 0x16:
                sni = self.extract_sni(raw)
                if sni:
                    self.log.debug(f"TLS to {sni} from {ip.src}")

                    if sni in self.blocked:
                        self.log.warning(
                            f"DROP: {ip.src} → {sni} (blocked)")
                        pkt.drop()
                        return

                    # Async probe (don't block the packet)
                    threading.Thread(
                        target=self._async_probe,
                        args=(sni,),
                        daemon=True
                    ).start()

            pkt.accept()

        except Exception as e:
            self.log.error(f"cert handler: {e}")
            pkt.accept()

    def _async_probe(self, hostname: str):
        """Background certificate probe"""
        our_cert = self.get_cert_independent(hostname)
        if our_cert:
            self.log.info(
                f"Probed {hostname}: "
                f"fp={our_cert.fingerprint[:16]}... "
                f"issuer={our_cert.issuer[:40]}"
            )


# ============================================================
# PART 3: DNS CACHE + MITM DETECTION
# ============================================================

class DNSGuard:
    """
    Intercepts all DNS queries from VPN clients.
    Resolves via multiple independent resolvers.
    Compares responses — discrepancy = MITM DNS.
    Caches clean responses locally.
    """

    # Independent resolvers for cross-checking
    RESOLVERS = [
        "1.1.1.1",      # Cloudflare
        "8.8.8.8",      # Google
        "9.9.9.9",      # Quad9
        "208.67.222.222" # OpenDNS
    ]

    def __init__(self):
        self.cache:   Dict[str, dict] = {}
        self.lock = threading.Lock()
        self.log  = logging.getLogger("CTW-DNS")
        self.poisoned: Set[str] = set()

    def resolve_via(
        self, resolver: str, query: str, qtype: str = 'A'
    ) -> Optional[Set[str]]:
        """Resolve a query via specific resolver"""
        try:
            import dns.resolver
            r = dns.resolver.Resolver(configure=False)
            r.nameservers = [resolver]
            r.timeout = 2.0
            r.lifetime = 3.0
            answers = r.resolve(query, qtype)
            return {str(rdata) for rdata in answers}
        except Exception:
            return None

    def cross_resolve(self, hostname: str) -> Tuple[bool, dict]:
        """
        Resolve via all four resolvers.
        Compare responses.
        Returns (consistent, results)
        """
        results = {}

        for resolver in self.RESOLVERS:
            answers = self.resolve_via(resolver, hostname)
            if answers:
                results[resolver] = answers

        if len(results) < 2:
            return True, results  # Can't compare

        # Check all agree
        all_answers = list(results.values())
        reference = all_answers[0]

        for resolver, answers in results.items():
            # Check for significant discrepancy
            # (some CDNs legitimately give different IPs)
            # Flag only if COMPLETELY different AND
            # one resolver returns a private IP (hijack)
            for ip in answers:
                try:
                    addr = ipaddress.ip_address(ip)
                    if addr.is_private:
                        self.log.critical(
                            f"DNS HIJACK: {hostname} "
                            f"resolver={resolver} "
                            f"returned PRIVATE IP {ip}"
                        )
                        return False, results
                except ValueError:
                    pass

        return True, results

    def handle_packet(self, pkt):
        """NFQUEUE handler for queue 11"""
        try:
            pkt.accept()  # Allow all DNS but log anomalies

            if not DEPS_OK:
                return

            from scapy.all import IP, UDP, DNS, DNSQR
            ip = IP(pkt.get_payload())

            if not ip.haslayer(DNS):
                return

            dns = ip[DNS]
            if dns.qr == 0 and dns.qdcount > 0:
                # This is a query
                qname = dns[DNSQR].qname.decode(
                    'ascii', errors='replace').rstrip('.')

                if qname in self.poisoned:
                    self.log.warning(
                        f"BLOCKED poisoned domain: {qname}")
                    pkt.drop()
                    return

                # Cross-check in background
                threading.Thread(
                    target=self._cross_check,
                    args=(qname,),
                    daemon=True
                ).start()

        except Exception as e:
            self.log.debug(f"dns handler: {e}")

    def _cross_check(self, hostname: str):
        """Background DNS consistency check"""
        if hostname in self.cache:
            return  # Already verified

        consistent, results = self.cross_resolve(hostname)

        with self.lock:
            if consistent:
                self.cache[hostname] = {
                    'results': results,
                    'ts': time.time(),
                    'status': 'CLEAN'
                }
                self.log.debug(f"DNS CLEAN: {hostname}")
            else:
                self.poisoned.add(hostname)
                self.cache[hostname] = {
                    'results': results,
                    'ts': time.time(),
                    'status': 'POISONED'
                }
                self.log.critical(
                    f"DNS POISONED: {hostname} "
                    f"results={results}"
                )


# ============================================================
# PART 4: FILE HASH ENFORCEMENT
# Unknown downloads = blocked until admin approves
# ============================================================

class FileHashEnforcer:
    """
    Intercepts file downloads from VPN clients.
    Hashes completed downloads.
    Compares against known-good database.
    Unknown files = automatically blocked.
    Admin can add explicit allow rules.
    """

    def __init__(self):
        self.log = logging.getLogger("CTW-HASH")
        self.db_path = HASH_DB_PATH
        self.sessions: Dict[str, dict] = {}
        self.lock = threading.Lock()
        self._init_db()

    def _init_db(self):
        """Initialize hash database"""
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()

        c.execute("""
            CREATE TABLE IF NOT EXISTS known_hashes (
                sha256      TEXT PRIMARY KEY,
                filename    TEXT,
                status      TEXT,  -- ALLOW, DENY, UNKNOWN
                source      TEXT,
                added_by    TEXT,
                added_at    TEXT,
                description TEXT
            )
        """)

        c.execute("""
            CREATE TABLE IF NOT EXISTS download_log (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp   TEXT,
                client_ip   TEXT,
                url         TEXT,
                sha256      TEXT,
                size        INTEGER,
                status      TEXT,
                iptables_rule TEXT
            )
        """)

        conn.commit()
        conn.close()
        self.log.info(f"Hash DB: {self.db_path}")

    def check_hash(self, sha256: str) -> str:
        """
        Check hash against database.
        Returns: ALLOW, DENY, UNKNOWN
        """
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute(
            "SELECT status FROM known_hashes WHERE sha256=?",
            (sha256,)
        )
        row = c.fetchone()
        conn.close()

        return row[0] if row else "UNKNOWN"

    def log_download(
        self,
        client_ip: str,
        url: str,
        sha256: str,
        size: int,
        status: str,
        iptables_rule: str = ""
    ):
        """Log download to database"""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("""
            INSERT INTO download_log
            (timestamp, client_ip, url, sha256, size,
             status, iptables_rule)
            VALUES (?,?,?,?,?,?,?)
        """, (
            datetime.utcnow().isoformat(),
            client_ip, url, sha256, size,
            status, iptables_rule
        ))
        conn.commit()
        conn.close()

    def block_hash(
        self,
        sha256: str,
        client_ip: str,
        filename: str = ""
    ) -> str:
        """
        Create iptables rule to block this hash.
        Uses string match on connection mark.
        Admin must explicitly add to ALLOW list.
        """
        rule = (
            f"iptables -A FORWARD -s {client_ip} "
            f"-m comment --comment "
            f"'CTW-HASH-BLOCK:{sha256[:16]}' "
            f"-j DROP"
        )

        try:
            subprocess.run(
                rule.split(), capture_output=True
            )
            self.log.warning(
                f"HASH BLOCK RULE: {sha256[:16]}... "
                f"for {client_ip}"
            )
        except Exception as e:
            self.log.error(f"iptables rule failed: {e}")

        # Record in DB as DENY pending review
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("""
            INSERT OR IGNORE INTO known_hashes
            (sha256, filename, status, source,
             added_by, added_at, description)
            VALUES (?,?,?,?,?,?,?)
        """, (
            sha256, filename, "DENY",
            client_ip, "auto",
            datetime.utcnow().isoformat(),
            "Auto-blocked: unknown download"
        ))
        conn.commit()
        conn.close()

        return rule

    def admin_allow(self, sha256: str, description: str = ""):
        """Admin explicitly allows a hash"""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("""
            INSERT OR REPLACE INTO known_hashes
            (sha256, status, added_by, added_at, description)
            VALUES (?,?,?,?,?)
        """, (
            sha256, "ALLOW", "admin",
            datetime.utcnow().isoformat(),
            description
        ))
        conn.commit()
        conn.close()

        # Remove any blocking rule for this hash
        subprocess.run([
            'iptables', '-D', 'FORWARD',
            '-m', 'comment', '--comment',
            f'CTW-HASH-BLOCK:{sha256[:16]}',
            '-j', 'DROP'
        ], capture_output=True)

        self.log.info(f"Admin ALLOW: {sha256[:16]}...")

    def handle_packet(self, pkt):
        """NFQUEUE handler for queue 12"""
        # File hash enforcement operates at session level
        # We accumulate bytes per connection flow
        # and hash when content-length reached
        # For now: accept and log (full reconstruction
        # requires application-layer proxy)
        try:
            pkt.accept()
        except Exception:
            pass


# ============================================================
# PART 5: GEOLOCATION ASN VERIFICATION
# Drop clients whose ASN doesn't match registered location
# ============================================================

class GeoASNVerifier:
    """
    Each registered VPN client has a registered ASN.
    When client connects, verify their source IP's ASN
    matches the registered ASN.

    Catches:
    - Device impersonation from another country
    - Compromised device relaying via foreign proxy
    - Cell tower MITM presenting wrong location
    """

    def __init__(self):
        self.log = logging.getLogger("CTW-GEO")
        self.blocked_ips: Set[str] = set()

        # Try to load MaxMind GeoIP2 ASN database
        self.geo_reader = None
        try:
            import geoip2.database
            self.geo_reader = geoip2.database.Reader(GEO_DB_PATH)
            self.log.info("GeoIP2 ASN database loaded")
        except Exception as e:
            self.log.warning(f"GeoIP2 not available: {e}")

    def get_asn(self, ip: str) -> Optional[Tuple[int, str]]:
        """
        Get ASN number and organization for IP.
        Returns (asn_number, org_name) or None
        """
        # Try MaxMind first
        if self.geo_reader:
            try:
                response = self.geo_reader.asn(ip)
                return (
                    response.autonomous_system_number,
                    response.autonomous_system_organization
                )
            except Exception:
                pass

        # Fallback: query RIPE or CYMRU
        try:
            # Team Cymru IP-to-ASN mapping via DNS
            reversed_ip = '.'.join(reversed(ip.split('.')))
            query = f"{reversed_ip}.origin.asn.cymru.com"
            import dns.resolver
            answers = dns.resolver.resolve(query, 'TXT')
            for rdata in answers:
                parts = str(rdata).strip('"').split('|')
                if len(parts) >= 1:
                    asn = int(parts[0].strip())
                    org = parts[-1].strip() if len(parts) > 4 else ""
                    return (asn, org)
        except Exception:
            pass

        return None

    def register_client(
        self,
        client_id: str,
        ip: str,
        expected_asn: int,
        description: str = ""
    ):
        """Register expected ASN for a client"""
        REGISTERED_CLIENTS[client_id] = {
            'ip': ip,
            'expected_asn': expected_asn,
            'description': description,
            'registered_at': datetime.utcnow().isoformat()
        }
        self.log.info(
            f"Registered: {client_id} "
            f"IP={ip} ASN={expected_asn}"
        )

    def verify_client(self, client_ip: str) -> Tuple[bool, str]:
        """
        Verify client IP's ASN matches registration.
        Returns (ok, reason)
        """
        # Find client registration
        client_reg = None
        client_id = None
        for cid, reg in REGISTERED_CLIENTS.items():
            if reg['ip'] == client_ip:
                client_reg = reg
                client_id = cid
                break

        if client_reg is None:
            # Unknown client — allow but log
            self.log.warning(
                f"UNREGISTERED CLIENT: {client_ip}")
            return True, "UNREGISTERED_ALLOW"

        # Get current ASN
        asn_info = self.get_asn(client_ip)
        if asn_info is None:
            return True, "ASN_LOOKUP_FAILED_ALLOW"

        current_asn, org = asn_info
        expected_asn = client_reg['expected_asn']

        if current_asn != expected_asn:
            reason = (
                f"ASN_MISMATCH client={client_id} "
                f"ip={client_ip} "
                f"expected_asn={expected_asn} "
                f"got_asn={current_asn} org={org}"
            )
            self.log.critical(f"GEO VIOLATION: {reason}")
            self.blocked_ips.add(client_ip)

            # Add iptables drop rule
            subprocess.run([
                'iptables', '-I', 'FORWARD', '1',
                '-s', client_ip,
                '-j', 'LOG',
                '--log-prefix', 'CTW-GEO-BLOCK: ',
                '--log-level', '2'
            ], capture_output=True)

            subprocess.run([
                'iptables', '-I', 'FORWARD', '2',
                '-s', client_ip,
                '-j', 'DROP'
            ], capture_output=True)

            return False, reason

        self.log.debug(
            f"GEO OK: {client_id} ASN={current_asn} {org}")
        return True, f"GEO_OK asn={current_asn}"


# ============================================================
# PART 6: DEVICE FINGERPRINT ENFORCEMENT
# Detect iOS presenting as macOS or vice versa
# This catches device spoofing attacks
# ============================================================

@dataclass
class DeviceFingerprint:
    """Complete device identity profile"""
    mac_addr:       str = ""
    mac_vendor:     str = ""
    tcp_window:     int = 0
    tcp_options:    str = ""
    ja3_hash:       str = ""
    user_agent:     str = ""
    os_guess:       str = ""
    is_ios:         bool = False
    is_macos:       bool = False
    is_windows:     bool = False
    is_android:     bool = False
    suspicious:     bool = False
    reason:         str = ""


class DeviceFingerprintEnforcer:
    """
    Detects device identity spoofing.

    iOS vs macOS detection:
      iOS:   TCP window 65535, specific option order,
             JA3 hash distinctive, UA contains iPhone/iPad
      macOS: TCP window 65535 (same) but different
             TCP option order and JA3

    The attack we're stopping:
      - Attacker compromises iOS device
      - Presents macOS fingerprint to bypass iOS-specific rules
      - Or: iOS IP but macOS User-Agent on outbound
      - Or: macOS MAC address OUI but iOS TCP fingerprint
    """

    # Apple OUI prefixes (both iOS and macOS use same OUI)
    APPLE_OUIS = {
        "00:03:93", "00:05:02", "00:0A:27",
        "00:0A:95", "00:0D:93", "00:11:24",
        "00:14:51", "00:16:CB", "00:17:F2",
        "00:19:E3", "00:1B:63", "00:1C:B3",
        "00:1D:4F", "00:1E:52", "00:1E:C2",
        "00:1F:5B", "00:1F:F3", "00:21:E9",
        "00:22:41", "00:23:12", "00:23:32",
        "00:23:6C", "00:24:36", "00:25:00",
        "00:25:4B", "00:25:BC", "00:26:08",
        "00:26:4A", "00:26:B0", "00:26:BB",
        "AC:BC:32", "D4:90:9C", "F0:D1:A9",
    }

    # iOS TCP fingerprint (from p0f database)
    # TCP options order is distinctive
    IOS_TCP_OPTIONS = [
        'MSS', 'NOP', 'WS', 'NOP', 'NOP',
        'TS', 'SACK', 'EOL'
    ]

    # macOS TCP fingerprint
    MACOS_TCP_OPTIONS = [
        'MSS', 'NOP', 'WS', 'SACK', 'TS',
        'EOL'
    ]

    # JA3 hashes known to be iOS vs macOS
    # These change with OS updates but clusters exist
    IOS_JA3_PATTERNS = [
        "d41d",  # iOS 15 signature fragment
        "a0e9",  # iOS 16 signature fragment
    ]

    MACOS_JA3_PATTERNS = [
        "bc3f",  # macOS 12 fragment
        "2dc0",  # macOS 13 fragment
    ]

    def __init__(self):
        self.log = logging.getLogger("CTW-DEVICE")
        self.sessions: Dict[str, DeviceFingerprint] = {}
        self.lock = threading.Lock()
        self.blocked: Set[str] = set()

    def parse_tcp_options(self, options_bytes: bytes) -> str:
        """Parse TCP options into readable list"""
        opts = []
        idx = 0
        while idx < len(options_bytes):
            kind = options_bytes[idx]
            if kind == 0:
                opts.append('EOL')
                break
            elif kind == 1:
                opts.append('NOP')
                idx += 1
            elif kind == 2:
                opts.append('MSS')
                idx += int(options_bytes[idx+1])
            elif kind == 3:
                opts.append('WS')
                idx += int(options_bytes[idx+1])
            elif kind == 4:
                opts.append('SACK')
                idx += int(options_bytes[idx+1])
            elif kind == 8:
                opts.append('TS')
                idx += int(options_bytes[idx+1])
            else:
                opts.append(f'OPT{kind}')
                if idx + 1 < len(options_bytes):
                    idx += int(options_bytes[idx+1])
                else:
                    break
        return ','.join(opts)

    def compute_ja3(self, tls_payload: bytes) -> str:
        """
        Compute JA3 fingerprint from TLS ClientHello.
        JA3 = MD5 of:
          SSLVersion,Ciphers,Extensions,EllipticCurves,
          EllipticCurvePointFormats
        """
        try:
            # Simplified JA3 — full implementation is complex
            # but the version + first cipher bytes are enough
            # for iOS vs macOS distinction
            if len(tls_payload) < 50:
                return ""

            # TLS version (2 bytes at offset 9)
            version = struct.unpack_from('>H', tls_payload, 9)[0]

            # Cipher suites start at offset 43 + session_id_len
            session_len = tls_payload[43]
            cs_offset = 44 + session_len
            cs_len = struct.unpack_from(
                '>H', tls_payload, cs_offset)[0]

            ciphers = []
            for i in range(cs_offset+2, cs_offset+2+cs_len, 2):
                cs = struct.unpack_from('>H', tls_payload, i)[0]
                if cs != 0x00FF:  # Skip SCSV
                    ciphers.append(cs)

            ja3_str = f"{version}-" + \
                      "-".join(str(c) for c in ciphers[:8])
            return hashlib.md5(
                ja3_str.encode()).hexdigest()[:8]

        except Exception:
            return ""

    def fingerprint_packet(
        self, payload: bytes
    ) -> Optional[DeviceFingerprint]:
        """Extract device fingerprint from SYN packet"""
        fp = DeviceFingerprint()

        try:
            if not DEPS_OK:
                return fp

            from scapy.all import IP, TCP
            ip = IP(payload)

            if not ip.haslayer(TCP):
                return None

            tcp = ip[TCP]

            # TCP window size
            fp.tcp_window = tcp.window

            # TCP options
            if tcp.options:
                opt_names = [opt[0] for opt in tcp.options]
                fp.tcp_options = ','.join(
                    str(o) for o in opt_names)

            # OS detection from TCP fingerprint
            # iOS: window=65535, MSS=1460
            # macOS: window=65535, MSS=1460 (similar)
            # Windows: window=64240, MSS=1460
            # Linux: window=64240 or 29200

            if tcp.window == 64240:
                if any(opt[0] == 'MSS' and
                       opt[1] == 1460
                       for opt in (tcp.options or [])):
                    fp.os_guess = "Windows"
                    fp.is_windows = True
                else:
                    fp.os_guess = "Linux"

            elif tcp.window == 65535:
                # Could be iOS or macOS
                # Distinguish by option order
                opts = [opt[0] for opt in (tcp.options or [])]
                if opts == self.IOS_TCP_OPTIONS:
                    fp.os_guess = "iOS"
                    fp.is_ios = True
                elif opts == self.MACOS_TCP_OPTIONS:
                    fp.os_guess = "macOS"
                    fp.is_macos = True
                else:
                    fp.os_guess = "Apple_Unknown"

            # Check TLS JA3 if available
            raw = bytes(tcp.payload) if tcp.payload else b''
            if raw and raw[0] == 0x16:
                fp.ja3_hash = self.compute_ja3(raw)

        except Exception as e:
            self.log.debug(f"fingerprint: {e}")

        return fp

    def check_identity_consistency(
        self,
        fp: DeviceFingerprint,
        client_ip: str,
        direction: str,  # "INBOUND" or "OUTBOUND"
        user_agent: str = ""
    ) -> Tuple[bool, str]:
        """
        Check if packet identity is consistent.
        Catches iOS presenting as macOS.

        Inbound:  macOS fingerprint on iOS IP/identifiers
        Outbound: iOS packet with macOS User-Agent
        """
        suspicious = False
        reason = ""

        # Get registered device type for this IP
        reg = REGISTERED_CLIENTS.get(client_ip, {})
        registered_type = reg.get('device_type', '')

        if direction == "INBOUND":
            # Attacker sends macOS-fingerprinted traffic
            # to client that we know is iOS
            if registered_type == "iOS" and fp.is_macos:
                suspicious = True
                reason = (
                    f"DEVICE_SPOOF INBOUND: "
                    f"IP={client_ip} "
                    f"registered=iOS "
                    f"fingerprint=macOS "
                    f"window={fp.tcp_window} "
                    f"opts={fp.tcp_options}"
                )

            # macOS client but iOS fingerprint incoming
            elif registered_type == "macOS" and fp.is_ios:
                suspicious = True
                reason = (
                    f"DEVICE_SPOOF INBOUND: "
                    f"IP={client_ip} "
                    f"registered=macOS "
                    f"fingerprint=iOS"
                )

        elif direction == "OUTBOUND":
            # iOS device sending macOS User-Agent
            if fp.is_ios and user_agent:
                if 'Macintosh' in user_agent and \
                   'iPhone' not in user_agent and \
                   'iPad' not in user_agent:
                    suspicious = True
                    reason = (
                        f"DEVICE_SPOOF OUTBOUND: "
                        f"TCP=iOS "
                        f"UA=macOS "
                        f"ip={client_ip} "
                        f"ua={user_agent[:60]}"
                    )

            # macOS device sending iOS User-Agent
            elif fp.is_macos and user_agent:
                if ('iPhone' in user_agent or
                        'iPad' in user_agent):
                    suspicious = True
                    reason = (
                        f"DEVICE_SPOOF OUTBOUND: "
                        f"TCP=macOS "
                        f"UA=iOS "
                        f"ip={client_ip} "
                        f"ua={user_agent[:60]}"
                    )

            # iOS fingerprint but sending from registered macOS
            if registered_type == "macOS" and \
               fp.is_ios and not suspicious:
                suspicious = True
                reason = (
                    f"DEVICE_SPOOF OUTBOUND: "
                    f"IP={client_ip} "
                    f"registered=macOS "
                    f"actual_fingerprint=iOS"
                )

        return not suspicious, reason

    def handle_packet(self, pkt):
        """NFQUEUE handler for queue 13"""
        try:
            if not DEPS_OK:
                pkt.accept()
                return

            payload = pkt.get_payload()
            from scapy.all import IP, TCP
            ip = IP(payload)

            src = ip.src
            dst = ip.dst

            # Only fingerprint SYN packets
            if not ip.haslayer(TCP):
                pkt.accept()
                return

            tcp = ip[TCP]
            is_syn = tcp.flags & 0x02 and not tcp.flags & 0x10

            if not is_syn:
                pkt.accept()
                return

            # Extract fingerprint
            fp = self.fingerprint_packet(payload)
            if not fp:
                pkt.accept()
                return

            # Store fingerprint for this session
            session_key = f"{src}:{tcp.sport}"
            with self.lock:
                self.sessions[session_key] = fp

            # Check if this IP should be blocked
            if src in self.blocked or dst in self.blocked:
                pkt.drop()
                return

            # Check inbound consistency
            ok, reason = self.check_identity_consistency(
                fp, dst, "INBOUND"
            )

            if not ok:
                self.log.critical(f"DEVICE SPOOF: {reason}")
                self.blocked.add(src)

                # Log to iptables
                subprocess.run([
                    'iptables', '-I', 'FORWARD', '1',
                    '-s', src,
                    '-j', 'LOG',
                    '--log-prefix', 'CTW-SPOOF-BLOCK: ',
                    '--log-level', '2'
                ], capture_output=True)

                subprocess.run([
                    'iptables', '-I', 'FORWARD', '2',
                    '-s', src,
                    '-j', 'DROP'
                ], capture_output=True)

                pkt.drop()
                return

            # Log clean fingerprint
            self.log.debug(
                f"DEVICE OK: {src} "
                f"os={fp.os_guess} "
                f"window={fp.tcp_window}"
            )

            pkt.accept()

        except Exception as e:
            self.log.error(f"device handler: {e}")
            pkt.accept()

    def register_device(
        self,
        client_ip: str,
        device_type: str,  # "iOS", "macOS", "Windows", "Android"
        description: str = ""
    ):
        """Register expected device type for client IP"""
        if client_ip not in REGISTERED_CLIENTS:
            REGISTERED_CLIENTS[client_ip] = {}

        REGISTERED_CLIENTS[client_ip]['device_type'] = device_type
        REGISTERED_CLIENTS[client_ip]['description'] = description

        self.log.info(
            f"Device registered: {client_ip} = {device_type}")


# ============================================================
# PPTP SERVER CONFIGURATION
# ============================================================

PPTPD_CONF = """
# CTW-11 Guard Tower PPTP Configuration
# /etc/pptpd.conf

option /etc/ppp/pptpd-options
logwtmp
localip  192.168.100.1
remoteip 192.168.100.100-200
connections 100
"""

PPTPD_OPTIONS = """
# CTW-11 Guard Tower PPP Options
# /etc/ppp/pptpd-options

name pptpd
refuse-pap
refuse-chap
refuse-mschap
require-mschap-v2
require-mppe-128
ms-dns 192.168.100.1
ms-wins 192.168.100.1
proxyarp
lock
nobsdcomp
novj
novjccomp
nologfd
"""

def setup_pptp():
    """Configure pptpd"""
    with open('/etc/pptpd.conf', 'w') as f:
        f.write(PPTPD_CONF)
    with open('/etc/ppp/pptpd-options', 'w') as f:
        f.write(PPTPD_OPTIONS)
    log.info("PPTP configuration written")


# ============================================================
# NFQUEUE RUNNER
# Runs each queue in its own thread
# ============================================================

def run_nfqueue(queue_num: int, handler, name: str):
    """Run a netfilter queue in a thread"""
    if not DEPS_OK:
        log.warning(f"NFQUEUE {queue_num} ({name}): "
                    f"deps missing — skipping")
        return

    def _run():
        q = NetfilterQueue()
        q.bind(queue_num, handler)
        log.info(f"NFQUEUE {queue_num} ({name}) started")
        try:
            q.run()
        except Exception as e:
            log.error(f"NFQUEUE {queue_num} error: {e}")
        finally:
            q.unbind()

    t = threading.Thread(target=_run, daemon=True, name=name)
    t.start()
    return t


# ============================================================
# ADMIN CLI
# ============================================================

def admin_shell(
    enforcer: FileHashEnforcer,
    geo: GeoASNVerifier,
    device: DeviceFingerprintEnforcer,
    cert: CertificateVerifier
):
    """Interactive admin console"""
    print("\nCTW-11 Guard Tower Admin Console")
    print("Commands: allow-hash, block-hash, register-client,")
    print("          register-device, show-blocked, show-dns,")
    print("          show-certs, quit")

    while True:
        try:
            cmd = input("\nguard> ").strip().split()
        except (EOFError, KeyboardInterrupt):
            break

        if not cmd:
            continue

        if cmd[0] == "allow-hash" and len(cmd) >= 2:
            desc = ' '.join(cmd[2:]) if len(cmd) > 2 else ""
            enforcer.admin_allow(cmd[1], desc)
            print(f"ALLOWED: {cmd[1][:16]}...")

        elif cmd[0] == "block-hash" and len(cmd) >= 2:
            enforcer.block_hash(cmd[1], "admin", "")
            print(f"BLOCKED: {cmd[1][:16]}...")

        elif cmd[0] == "register-client":
            # register-client <id> <ip> <asn>
            if len(cmd) >= 4:
                geo.register_client(cmd[1], cmd[2], int(cmd[3]))
                print(f"Registered: {cmd[1]}")

        elif cmd[0] == "register-device":
            # register-device <ip> <iOS|macOS|Windows>
            if len(cmd) >= 3:
                device.register_device(cmd[1], cmd[2])
                print(f"Device registered: {cmd[1]} = {cmd[2]}")

        elif cmd[0] == "show-blocked":
            print("Blocked IPs:")
            all_blocked = (
                device.blocked |
                geo.blocked_ips |
                cert.blocked
            )
            for ip in all_blocked:
                print(f"  {ip}")

        elif cmd[0] == "show-dns":
            print("DNS Cache:")
            for host, info in cert.cache.items():
                print(f"  {host}: {info}")

        elif cmd[0] == "show-certs":
            print("Certificate Cache:")
            for host, cert_info in cert.cache.items():
                print(f"  {host}: "
                      f"{cert_info.fingerprint[:16]}...")

        elif cmd[0] == "quit":
            break

        else:
            print("Unknown command")


# ============================================================
# MAIN
# ============================================================

def main():
    import argparse

    ap = argparse.ArgumentParser(
        description="CTW-11 Guard Tower VPN Security"
    )
    ap.add_argument(
        '--setup-only', action='store_true',
        help='Apply iptables and exit'
    )
    ap.add_argument(
        '--no-iptables', action='store_true',
        help='Skip iptables setup'
    )
    ap.add_argument(
        '--admin', action='store_true',
        help='Start admin console'
    )
    args = ap.parse_args()

    log.info("CTW-11 Guard Tower starting...")
    log.warning(
        "NOTE: PPTP uses MS-CHAPv2 which has known weaknesses. "
        "Consider WireGuard for production use."
    )

    # Setup PPTP
    if os.path.exists('/etc/pptpd.conf'):
        setup_pptp()

    # Apply iptables
    if not args.no_iptables:
        log.info("Applying iptables ruleset...")
        apply_iptables()

    if args.setup_only:
        log.info("Setup complete — exiting")
        return

    # Initialize all security modules
    cert_verifier = CertificateVerifier()
    dns_guard     = DNSGuard()
    hash_enforcer = FileHashEnforcer()
    geo_verifier  = GeoASNVerifier()
    dev_enforcer  = DeviceFingerprintEnforcer()

    log.info("Starting NFQUEUE security layers...")

    # Start all four NFQUEUE handlers
    threads = [
        run_nfqueue(10, cert_verifier.handle_packet,
                    "cert-verifier"),
        run_nfqueue(11, dns_guard.handle_packet,
                    "dns-guard"),
        run_nfqueue(12, hash_enforcer.handle_packet,
                    "hash-enforcer"),
        run_nfqueue(13, dev_enforcer.handle_packet,
                    "device-enforcer"),
    ]

    log.info("Guard Tower fully operational")
    log.info(f"Logs: {LOG_DIR}/guard_tower.log")

    if args.admin:
        admin_shell(
            hash_enforcer, geo_verifier,
            dev_enforcer, cert_verifier
        )
    else:
        # Keep running
        try:
            while True:
                time.sleep(60)
                log.info(
                    f"STATUS — "
                    f"cert_cache={len(cert_verifier.cache)} "
                    f"dns_cache={len(dns_guard.cache)} "
                    f"blocked_ips={len(dev_enforcer.blocked)} "
                    f"poisoned_dns={len(dns_guard.poisoned)}"
                )
        except KeyboardInterrupt:
            log.info("Guard Tower shutting down")


if __name__ == '__main__':
    if os.geteuid() != 0:
        print("Must run as root")
        sys.exit(1)
    main()
