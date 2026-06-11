#!/bin/sh
# =============================================================================
# Device-identity guard — add-on to the OpenVPN gateway
# A device that should present as iOS must keep presenting as iOS. Its TLS
# fingerprint is matched against LEARNED iOS/macOS JA3 sets:
#   - JA3 in the macOS set   -> DROP + log  (Mac impersonation)
#   - JA3 NOT in the iOS set  -> LOG         (divergence from the iOS baseline,
#                                            including anything that is neither)
#   - JA3 in the iOS set      -> passes silently
#
# READ FIRST — what is / isn't visible at a VPN server:
#  * MAC address: NOT available. MACs are layer-2, stripped at the client's
#    first-hop router; they never cross the internet, and `dev tun` is layer-3
#    (no Ethernet at all). The cert-bound tunnel IP (pinned below) is the
#    spoof-resistant anchor that replaces it.
#  * TCP/IP stack fingerprint (p0f): iOS and macOS share the Darwin/XNU stack,
#    so passive TCP fingerprinting cannot reliably separate them -- not used.
#  * TLS JA3/JA4 IS visible without decryption (the ClientHello is cleartext)
#    and is the real discriminator here. JA4 (Suricata >=7) is the stronger,
#    more stable fingerprint; swap ja3.hash -> ja4.hash with parallel JA4 sets.
#  * Direction: fingerprinting is OUTBOUND -- the device's identity is in what
#    IT sends (the ClientHello, flow:to_server). Inbound packets carry the
#    remote peer's fingerprint, not the device's, so section 3 is a stateful +
#    port heuristic, not fingerprinting.
#  * The User-Agent "Macintosh" substring rule is intentionally NOT the
#    mechanism (trivially forged; "like Mac OS X" appears in iOS UAs too). JA3/
#    JA4 sets do the detection; UA can ride along only as weak corroboration.
# =============================================================================

IOS_CLIENT_CN="client1"          # certificate CN of the iOS device
IOS_DEVICE_IP="10.8.0.10"        # static tunnel IP pinned to it
mkdir -p /etc/suricata/datasets

# ---- 1. Pin a stable, cert-bound tunnel IP to the iOS device (the anchor) ---
# Add to /etc/openvpn/server/server.conf, then restart openvpn-server@server:
#     client-config-dir /etc/openvpn/server/ccd
#     ifconfig-pool-persist /etc/openvpn/server/ipp.txt
mkdir -p /etc/openvpn/server/ccd
cat > /etc/openvpn/server/ccd/$IOS_CLIENT_CN <<EOF
ifconfig-push $IOS_DEVICE_IP 255.255.255.0
EOF
# $IOS_DEVICE_IP belongs to whoever holds the $IOS_CLIENT_CN key -- an attacker
# cannot claim that tunnel IP without the client certificate.

# ---- 2. Define the JA3 datasets in suricata.yaml ---------------------------
# Define the sets centrally (not inline per-rule) so the same named set isn't
# redefined in multiple rules. Inline "dataset:...,load <file>" also works in
# recent Suricata (>=6 dependable; 5.0 introduced datasets) but central is
# cleaner. Add this block to suricata.yaml:
#
#   datasets:
#     ios_ja3:
#       type: string
#       state: /etc/suricata/datasets/ios-ja3.lst
#     macos_ja3:
#       type: string
#       state: /etc/suricata/datasets/macos-ja3.lst
#
# FORMAT (the part that silently breaks setups): ja3.hash is a STRING buffer,
# so the set type is `string`, whose on-disk entries are BASE64-encoded -- not
# hex. Do NOT hand-write hex MD5s; they will never match. Let the LEARN rules
# below have Suricata write the entries in the correct encoding. If you must
# add one by hand:   printf %s '<ja3_hex>' | base64

# ---- 2a. LEARN phase -- build the baselines, NO enforcement ----------------
# Enable ONLY these two rules first. `dataset:set` adds each observed JA3 to the
# state file (and alerts so you watch it populate). Drive the iOS device across
# every app you care about; separately run the Mac you are baselining through
# the tunnel as its own client. Requires $MACOS_BASELINE defined in suricata.yaml.
cat > /etc/suricata/rules/osguard-learn.rules <<'EOF'
alert tls $IOS_DEVICE any -> any any (msg:"OSGUARD LEARN iOS JA3"; \
    flow:to_server; ja3.hash; dataset:set,ios_ja3; \
    sid:1000030; rev:1;)
alert tls $MACOS_BASELINE any -> any any (msg:"OSGUARD LEARN macOS JA3"; \
    flow:to_server; ja3.hash; dataset:set,macos_ja3; \
    sid:1000031; rev:1;)
EOF

# ---- 2b. ENFORCE phase -- swap to these once the sets are populated --------
# macOS match -> drop + log ; not-in-iOS -> log the divergence.
# Empty-set behaviour is deliberate and safe: empty macos set never matches
# (zero drops until you have baselined a Mac); empty ios set makes the
# divergence rule log EVERY handshake (your baselining feed) until populated,
# after which it logs only genuine divergence.
cat > /etc/suricata/rules/osguard.rules <<'EOF'
drop tls $IOS_DEVICE any -> any any (msg:"OSGUARD macOS JA3 from iOS device - dropped"; \
    flow:to_server; ja3.hash; dataset:isset,macos_ja3; \
    sid:1000020; rev:1;)
alert tls $IOS_DEVICE any -> any any (msg:"OSGUARD JA3 diverges from iOS baseline"; \
    flow:to_server; ja3.hash; dataset:isnotset,ios_ja3; \
    sid:1000021; rev:1;)
EOF

# ---- 3. INBOUND control (stateful + port heuristic, NOT fingerprinting) -----
# conntrack in the gateway firewall already drops inbound you didn't initiate.
# On top, drop+log inbound to the iOS tunnel IP on desktop-Mac service ports --
# an iPhone never offers AFP / screen sharing / Apple Remote Desktop.
IPT=/sbin/iptables
for p in 548 5900 3283; do
    $IPT -A FORWARD -d $IOS_DEVICE_IP -p tcp --dport $p -j LOG --log-prefix "OSGUARD inbound-mac-svc: "
    $IPT -A FORWARD -d $IOS_DEVICE_IP -p tcp --dport $p -j DROP
    $IPT -A FORWARD -d $IOS_DEVICE_IP -p udp --dport $p -j LOG --log-prefix "OSGUARD inbound-mac-svc: "
    $IPT -A FORWARD -d $IOS_DEVICE_IP -p udp --dport $p -j DROP
done

cat <<'CHECKLIST'

=========================== DEVICE-IDENTITY CHECKLIST ===========================
1. server.conf: add client-config-dir + ifconfig-pool-persist, restart OpenVPN.
2. suricata.yaml:
     - vars: address-groups:
         IOS_DEVICE: "[10.8.0.10]"
         MACOS_BASELINE: "[<mac tunnel IP, only during baselining>]"
     - datasets: block defining ios_ja3 + macos_ja3 (section 2)
     - app-layer.protocols.tls.ja3-fingerprints: yes   (ja4-fingerprints if >=7)
3. LEARN first:  rule-files: -> only "- osguard-learn.rules". Use the iOS device
   and the Mac across real apps. Confirm ios-ja3.lst / macos-ja3.lst fill.
4. ENFORCE: swap rule-files to "- osguard.rules", remove the learn file, restart.
   A macOS JA3 from the iOS device now drops; any JA3 outside the iOS baseline
   logs as divergence.
5. Version deps: datasets need Suricata >=5 (>=6 for dependable inline load);
   JA4 needs >=7 (prefer ja4.hash there). JA3s drift across OS/app versions --
   re-run LEARN periodically so the iOS baseline stays current and divergence
   logging does not fill with false positives.
6. Honest ceiling: JA3 is forgeable. An adversary who mimics an iOS JA3 passes.
   This catches automated/sloppy impersonation and gives you a divergence log;
   it raises the bar, it is not proof.
================================================================================
CHECKLIST
