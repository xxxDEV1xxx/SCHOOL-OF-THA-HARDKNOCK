#!/bin/sh
# =============================================================================
# Security VPN gateway — multi-layer build (OpenVPN transport)
# Supersedes the earlier PPTP base. Each of your 4 functions is implemented at
# the layer that can actually ENFORCE it, rather than forced into iptables:
#   transport : OpenVPN  -> 1194/udp, AES-256-GCM, tls-crypt
#   func 1    : reprober -> server-side TLS SPKI check (+ client-agent contract)
#   func 2    : Unbound  -> DNS cache + DNSSEC validation + DoT upstream
#   func 3    : Suricata -> inline IPS, drop files whose SHA256 isn't allowlisted
#   func 4    : iptables -> geoip source-country filter on the VPN port
#   kernel    : iptables default-deny + NFQUEUE handoff to Suricata
#
# Template for a clean Debian/Ubuntu box. Review every CONFIG value first.
# Not run-and-forget: see the CHECKLIST printed at the end.
# =============================================================================

set -u   # catch unset vars; intentionally NOT -e so one failed service
         # doesn't abort the rest (OpenVPN won't start until PKI exists, etc.)

# ---- decisions you make ----------------------------------------------------
WAN_IF="eth0"                            # interface facing the internet
VPN_SUBNET="10.8.0.0"
VPN_MASK="255.255.255.0"
VPN_GW_IP="10.8.0.1"                     # this box, inside the tunnel
ALLOW_CC="US"                            # ISO country clients may connect FROM (func 4)
DOT1="1.1.1.1@853#cloudflare-dns.com"    # DoT upstreams (func 2)
DOT2="9.9.9.9@853#dns.quad9.net"
NFQUEUE_NUM=0
# ----------------------------------------------------------------------------

echo "[*] installing packages"
apt-get update
apt-get install -y openvpn easy-rsa unbound unbound-anchor \
    suricata xtables-addons-common python3 python3-cryptography iptables

# =============================================================================
# TRANSPORT — OpenVPN server  (replaces PPTP; far stronger)
# =============================================================================
# PKI is generated ONCE, separately, BEFORE first start (OpenVPN will not run
# without it):
#   make-cadir /etc/openvpn/easy-rsa && cd /etc/openvpn/easy-rsa
#   ./easyrsa init-pki && ./easyrsa build-ca nopass
#   ./easyrsa build-server-full server nopass
#   ./easyrsa gen-dh
#   openvpn --genkey secret /etc/openvpn/server/ta.key
#   ./easyrsa build-client-full client1 nopass     # repeat per client
# Copy ca.crt, issued/server.crt, private/server.key, dh.pem -> /etc/openvpn/server/

cat > /etc/openvpn/server/server.conf <<EOF
port 1194
proto udp
dev tun
topology subnet

ca   /etc/openvpn/server/ca.crt
cert /etc/openvpn/server/server.crt
key  /etc/openvpn/server/server.key
dh   /etc/openvpn/server/dh.pem
tls-crypt /etc/openvpn/server/ta.key        # HMAC firewall on the control channel

server $VPN_SUBNET $VPN_MASK

# Force ALL client traffic + DNS through this gateway so funcs 2/3 can act on it
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS $VPN_GW_IP"

data-ciphers AES-256-GCM
data-ciphers-fallback AES-256-GCM
auth SHA256
tls-version-min 1.2

keepalive 10 120
persist-key
persist-tun
user nobody
group nogroup
verb 3
EOF

echo 1 > /proc/sys/net/ipv4/ip_forward
sed -i 's/^#\?net.ipv4.ip_forward.*/net.ipv4.ip_forward=1/' /etc/sysctl.conf

# =============================================================================
# FUNCTION 2 — Unbound: local cache + DNSSEC validation + DoT upstream
# =============================================================================
unbound-anchor -a /var/lib/unbound/root.key || true   # seed DNSSEC root trust anchor

cat > /etc/unbound/unbound.conf.d/vpn.conf <<EOF
server:
    interface: 0.0.0.0          # firewall (below) restricts :53 to tun0 only
    do-ip6: no
    access-control: $VPN_SUBNET/24 allow
    access-control: 127.0.0.0/8 allow
    access-control: 0.0.0.0/0 refuse
    do-tcp: yes
    # DNSSEC validation — cryptographic answer integrity (signed zones only;
    # most domains still aren't signed, so this is partial, not total, coverage)
    auto-trust-anchor-file: "/var/lib/unbound/root.key"
    harden-dnssec-stripped: yes
    val-clean-additional: yes
    # caching
    prefetch: yes
    cache-min-ttl: 60
    msg-cache-size: 64m
    rrset-cache-size: 128m
    hide-identity: yes
    hide-version: yes

forward-zone:
    name: "."
    forward-tls-upstream: yes   # DoT — protects the gateway->resolver path on the wire
    forward-addr: $DOT1
    forward-addr: $DOT2
EOF

# =============================================================================
# FUNCTION 3 — Suricata inline: drop files whose SHA256 isn't allowlisted
# =============================================================================
# Admin-managed allowlist (one SHA256 per line). EMPTY = drop every cleartext
# file until you populate it (that's the default-deny posture you specified).
touch /etc/suricata/allowed-hashes.txt

cat > /etc/suricata/rules/fileguard.rules <<'EOF'
# Drop any extracted file whose SHA256 is NOT in the allowlist.
# "!" = negation ("hash is not in this list"). Works on cleartext app protocols
# (HTTP/FTP/SMB/SMTP). HTTPS file bodies are invisible to Suricata without a
# TLS-terminating proxy in front of it -- see CHECKLIST.
drop http any any -> any any (msg:"FILEGUARD unknown file blocked"; \
    filestore; filesha256:!allowed-hashes.txt; sid:1000001; rev:1;)
EOF
# NOTE: this rule only does anything once file hashing is enabled in
# suricata.yaml -- two manual edits, see CHECKLIST (avoided auto-editing the
# YAML here because duplicate top-level keys would corrupt it).

# =============================================================================
# FUNCTION 1 — server-side TLS SPKI re-prober (+ client-agent contract)
# =============================================================================
# The gateway CANNOT see the cert a client received under TLS 1.3 (it's
# encrypted), so real detection needs a client agent reporting the SPKI hash it
# observed. This service: (a) independently probes the host and records the
# SPKI hash; (b) compares a client-reported hash to its own probe; on mismatch
# it logs and null-routes the destination IP pending admin review. A single
# probe shares the gateway's network path -- harden by also checking
# Certificate Transparency logs / DANE, not just this one vantage point.
cat > /usr/local/bin/cert_reprobe.py <<'PYEOF'
#!/usr/bin/env python3
import ssl, socket, hashlib, subprocess, sys
from cryptography import x509
from cryptography.hazmat.primitives import serialization

def spki_sha256(host, port=443, timeout=5):
    ctx = ssl.create_default_context()
    with socket.create_connection((host, port), timeout) as s:
        with ctx.wrap_socket(s, server_hostname=host) as ss:
            der = ss.getpeercert(binary_form=True)
    cert = x509.load_der_x509_certificate(der)
    spki = cert.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(spki).hexdigest()

def flag_and_drop(host):
    try:
        ip = socket.gethostbyname(host)
        subprocess.run(["iptables", "-I", "OUTPUT",  "-d", ip, "-j", "DROP"], check=False)
        subprocess.run(["iptables", "-I", "FORWARD", "-d", ip, "-j", "DROP"], check=False)
        print(f"FLAGGED + dropped {host} ({ip})")
    except Exception as e:
        print(f"flag error: {e}", file=sys.stderr)

# usage: cert_reprobe.py <host> [client_reported_spki_sha256]
if __name__ == "__main__":
    host = sys.argv[1]
    server_view = spki_sha256(host)
    print(f"{host} server-observed SPKI: {server_view}")
    if len(sys.argv) > 2:
        client_view = sys.argv[2].lower()
        if client_view != server_view:
            print(f"MISMATCH {host}: client={client_view} server={server_view}")
            flag_and_drop(host)
        else:
            print("match -- cert consistent across vantage points")
PYEOF
chmod +x /usr/local/bin/cert_reprobe.py

# =============================================================================
# KERNEL — iptables default-deny + func 4 geoip + NFQUEUE handoff to Suricata
# =============================================================================
IPT=/sbin/iptables

$IPT -F
$IPT -X
$IPT -P INPUT   DROP
$IPT -P FORWARD DROP
$IPT -P OUTPUT  DROP

$IPT -A INPUT  -i lo -j ACCEPT
$IPT -A OUTPUT -o lo -j ACCEPT
$IPT -A INPUT  -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
$IPT -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# FUNCTION 4: only accept OpenVPN connections sourced from $ALLOW_CC.
# Reality check: this checks where the source IP is REGISTERED, not where the
# device physically is. A proxy/VPN in $ALLOW_CC bypasses it, and mobile/CGNAT
# is often misgeolocated, so it will also drop some legit clients. Coarse
# filter that raises the bar -- not proof of identity.
$IPT -A INPUT -i $WAN_IF -p udp --dport 1194 -m geoip --src-cc $ALLOW_CC \
    -m conntrack --ctstate NEW -j ACCEPT
$IPT -A INPUT -i $WAN_IF -p udp --dport 1194 -j LOG --log-prefix "GEO-DROP VPN: "
$IPT -A INPUT -i $WAN_IF -p udp --dport 1194 -j DROP

# clients query Unbound (func 2) inside the tunnel only
$IPT -A INPUT -i tun0 -p udp --dport 53 -j ACCEPT
$IPT -A INPUT -i tun0 -p tcp --dport 53 -j ACCEPT

# admin SSH -- restrict the source in production:  -s <mgmt_ip>
$IPT -A INPUT -p tcp --dport 22 -j ACCEPT

# FUNCTION 3 handoff: forwarded client traffic -> Suricata inline, which drops
# files failing the SHA256 allowlist and accepts the rest.
# --queue-bypass = fail-OPEN if Suricata is down. Remove it for fail-CLOSED.
$IPT -A FORWARD -i tun0 -o $WAN_IF \
    -m conntrack --ctstate NEW,ESTABLISHED,RELATED \
    -j NFQUEUE --queue-num $NFQUEUE_NUM --queue-bypass
$IPT -A FORWARD -i $WAN_IF -o tun0 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# NAT for VPN clients reaching the internet
$IPT -t nat -A POSTROUTING -s $VPN_SUBNET/$VPN_MASK -o $WAN_IF -j MASQUERADE

# this box's own outbound: DNS+DoT upstream (func 2), HTTPS/HTTP for re-probes
# (func 1) and rule/AV updates (func 3), plus the OpenVPN data channel
$IPT -A OUTPUT -p udp --dport 53   -m conntrack --ctstate NEW -j ACCEPT
$IPT -A OUTPUT -p tcp --dport 53   -m conntrack --ctstate NEW -j ACCEPT
$IPT -A OUTPUT -p tcp --dport 853  -m conntrack --ctstate NEW -j ACCEPT
$IPT -A OUTPUT -p tcp --dport 443  -m conntrack --ctstate NEW -j ACCEPT
$IPT -A OUTPUT -p tcp --dport 80   -m conntrack --ctstate NEW -j ACCEPT
$IPT -A OUTPUT -p udp --dport 1194 -j ACCEPT
$IPT -A OUTPUT -o tun0 -j ACCEPT

# =============================================================================
# start services
# =============================================================================
echo "[*] enabling services"
systemctl enable --now unbound
systemctl enable --now openvpn-server@server     # fails until PKI exists (expected)
suricata -q $NFQUEUE_NUM -D -c /etc/suricata/suricata.yaml

cat <<'CHECKLIST'

=============================== CHECKLIST ===============================
Before this is actually functional, do these by hand:

1. OpenVPN PKI: generate it with easy-rsa (commands in the TRANSPORT
   section comments) and copy the files into /etc/openvpn/server/,
   then: systemctl restart openvpn-server@server

2. geoip DBs (func 4): the xt_geoip module needs country databases built:
     /usr/lib/xtables-addons/xt_geoip_dl
     /usr/lib/xtables-addons/xt_geoip_build -D /usr/share/xt_geoip *.csv
   (paths vary by distro; on some you also need xtables-addons-dkms)

3. Suricata file hashing (func 3): edit /etc/suricata/suricata.yaml --
     a) add  "- fileguard.rules"  under the existing  rule-files:  list
     b) set  file-store: { enabled: yes, force-hash: [sha256] }
   then restart suricata. NOTE: this only sees CLEARTEXT file transfers.
   To cover HTTPS downloads you must terminate TLS in front of Suricata
   (Squid ssl-bump or a TLS proxy) with your CA installed on the clients
   -- a deliberate, consent-based step on a network you administer.

4. func 1 client agent: cert_reprobe.py only detects a MITM if a client
   agent POSTs the SPKI hash it actually observed. Without that agent the
   single server-side probe shares this box's network path and can miss an
   on-path attacker upstream of the gateway. Pair it with CT-log / DANE
   checks for a second independent vantage point.
========================================================================
CHECKLIST
