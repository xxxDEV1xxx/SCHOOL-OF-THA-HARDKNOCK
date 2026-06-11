#!/bin/sh
# =============================================================================
# Device-identity guard — add-on to the OpenVPN gateway
# Goal: a device that should present as iOS must keep presenting as iOS.
# Traffic from it that fingerprints as desktop macOS is dropped + logged.
#
# READ FIRST — what is / isn't visible at a VPN server:
#  * MAC address: NOT available. MACs are layer-2 and are stripped at the
#    client's first-hop router; they never traverse the internet, and the
#    `dev tun` tunnel is layer-3 (no Ethernet headers at all). You cannot
#    filter on the client's hardware MAC here. The cert-bound tunnel IP
#    (pinned below via CCD) is the spoof-resistant anchor that replaces it.
#  * TCP/IP stack fingerprint (p0f): iOS and macOS share the Darwin/XNU
#    network stack, so passive TCP fingerprinting CANNOT reliably tell them
#    apart. Deliberately not used here -- it would only produce false results.
#  * Signals that DO discriminate iOS vs macOS at the gateway:
#       - HTTP User-Agent  (strong; cleartext only, or behind a TLS-term proxy)
#       - TLS JA3/JA4      (passive, no decryption; weaker iOS/macOS separation)
#  * Direction: OS fingerprinting is fundamentally OUTBOUND -- the device's
#    identity leaks in what IT sends. INBOUND packets carry the REMOTE peer's
#    fingerprint, not the device's, so there is no symmetric "inbound macOS
#    fingerprint" to match. The inbound control below is a stateful + port
#    heuristic, not fingerprinting (stated plainly so it's not mistaken for it).
# =============================================================================

IOS_CLIENT_CN="client1"          # the certificate CN of the iOS device
IOS_DEVICE_IP="10.8.0.10"        # the static tunnel IP we pin to it

# ---- 1. Pin a stable, cert-bound tunnel IP to the iOS device (the anchor) ---
# Add these two lines to /etc/openvpn/server/server.conf, then restart it:
#     client-config-dir /etc/openvpn/server/ccd
#     ifconfig-pool-persist /etc/openvpn/server/ipp.txt
mkdir -p /etc/openvpn/server/ccd
cat > /etc/openvpn/server/ccd/$IOS_CLIENT_CN <<EOF
ifconfig-push $IOS_DEVICE_IP 255.255.255.0
EOF
# $IOS_DEVICE_IP now belongs to whoever holds the $IOS_CLIENT_CN key --
# an attacker can't claim that tunnel IP without the client certificate.

# ---- 2. OUTBOUND OS-consistency rules (Suricata) ---------------------------
# In suricata.yaml define the device under  vars: address-groups:
#     IOS_DEVICE: "[10.8.0.10]"
# (or just hardcode the IP in the rules below)
cat > /etc/suricata/rules/osguard.rules <<'EOF'
# (A) STRONG, enforced: drop outbound HTTP from the iOS device whose
# User-Agent claims desktop macOS. Match "Macintosh" -- present in macOS UAs,
# absent from iOS. Do NOT match "Mac OS X": iOS UAs literally contain
# "like Mac OS X", so that would false-positive on every iPhone.
drop http $IOS_DEVICE any -> any any (msg:"OSGUARD iOS device sent macOS User-Agent"; \
    flow:to_server; http.user_agent; content:"Macintosh"; nocase; \
    sid:1000010; rev:1;)

# (B) OPTIONAL JA3 drop. JA3 logs automatically to eve.json once enabled
# (no rule needed to baseline -- just filter eve.json for $IOS_DEVICE_IP to
# learn this device's normal iOS JA3s). Once you've also baselined a real Mac,
# paste its JA3 MD5 below and uncomment to drop it. Caveat: JA3 overlaps
# between iOS/macOS and shifts with OS/app versions, so keep it maintained and
# expect some noise. For multiple macOS JA3s, add one rule each (or move to a
# Suricata `dataset`, syntax of which varies by version -- verify before use).
#drop tls $IOS_DEVICE any -> any any (msg:"OSGUARD iOS device used a macOS JA3"; \
#    flow:to_server; ja3.hash; content:"PASTE_KNOWN_MACOS_JA3_MD5_HERE"; \
#    sid:1000012; rev:1;)
EOF

# ---- 3. INBOUND control (stateful + port heuristic, NOT fingerprinting) -----
# Stateful return traffic is already handled in the gateway firewall (conntrack
# only lets back flows the device actually initiated). On top of that, drop+log
# inbound attempts to reach the iOS tunnel IP on services characteristic of a
# desktop Mac -- an iPhone should never be offering AFP, screen sharing, or ARD.
IPT=/sbin/iptables
for p in 548 5900 3283; do      # AFP / VNC screen-sharing / Apple Remote Desktop
    $IPT -A FORWARD -d $IOS_DEVICE_IP -p tcp --dport $p \
        -j LOG --log-prefix "OSGUARD inbound-mac-svc: "
    $IPT -A FORWARD -d $IOS_DEVICE_IP -p tcp --dport $p -j DROP
    $IPT -A FORWARD -d $IOS_DEVICE_IP -p udp --dport $p \
        -j LOG --log-prefix "OSGUARD inbound-mac-svc: "
    $IPT -A FORWARD -d $IOS_DEVICE_IP -p udp --dport $p -j DROP
done

cat <<'CHECKLIST'

=========================== DEVICE-IDENTITY CHECKLIST ===========================
1. server.conf: add  client-config-dir /etc/openvpn/server/ccd  and
   ifconfig-pool-persist /etc/openvpn/server/ipp.txt , then
   systemctl restart openvpn-server@server
2. suricata.yaml:
     - add  IOS_DEVICE: "[10.8.0.10]"                 under  vars: address-groups:
     - add  "- osguard.rules"                          under  rule-files:
     - set  app-layer.protocols.tls.ja3-fingerprints: yes
       (JA3 then appears in eve.json automatically; JA4 needs Suricata 7+)
   then restart suricata.
3. The User-Agent rule (A) only sees CLEARTEXT HTTP. To enforce it over HTTPS
   you need the TLS-terminating proxy already discussed for function 3.
4. Honest limit: an adversary who knows you fingerprint on UA/JA3 can simply
   send iOS-shaped values. This catches sloppy or automated impersonation --
   it is a tell, not a proof.
================================================================================
CHECKLIST
