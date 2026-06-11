#!/bin/sh
# VPN gateway — base firewall, default-deny.
# This is the "starting point" to extend; it does NOT yet implement
# functions 1-4 (those live in higher layers — see notes in chat).
#
# NOTE: PPTP/GRE rules are included as requested, but PPTP is not a
# secure transport. Prefer WireGuard/OpenVPN, or the stunnel+pppd setup
# from your listings, if security is the goal.

IPT=/sbin/iptables

# Reset
$IPT -F
$IPT -X

# Default-deny — THIS is what makes the box actually "filter".
# An accept-only ruleset (what you had) filters nothing, because
# iptables' built-in default is ACCEPT.
$IPT -P INPUT   DROP
$IPT -P FORWARD DROP
$IPT -P OUTPUT  DROP

# Loopback
$IPT -A INPUT  -i lo -j ACCEPT
$IPT -A OUTPUT -o lo -j ACCEPT

# Stateful: let replies for established flows back through.
# Without this, default-deny kills every return packet.
$IPT -A INPUT  -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
$IPT -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# --- Inbound services this box OFFERS ---
# PPTP control channel + GRE. Protocol 47 has no ports; load the conntrack
# helper (modprobe nf_conntrack_pptp) so the GRE flows tied to the control
# connection are tracked correctly.
$IPT -A INPUT  -p tcp --dport 1723 -m conntrack --ctstate NEW -j ACCEPT
$IPT -A INPUT  -p 47 -j ACCEPT
# Local DNS resolver (function 2) — clients query THIS box only
$IPT -A INPUT  -p udp --dport 53 -j ACCEPT
$IPT -A INPUT  -p tcp --dport 53 -j ACCEPT
# Admin access — in production, restrict the source to your mgmt host:
#   $IPT -A INPUT -p tcp -s <mgmt_ip> --dport 22 -j ACCEPT
$IPT -A INPUT  -p tcp --dport 22 -j ACCEPT

# --- Outbound this box INITIATES (needed because OUTPUT default is DROP) ---
# GRE out (PPTP), resolver upstream (DNS + DoT), and HTTP/HTTPS for cert
# re-probes (function 1) and Suricata/AV rule updates (function 3).
$IPT -A OUTPUT -p 47 -j ACCEPT
$IPT -A OUTPUT -p udp --dport 53  -m conntrack --ctstate NEW -j ACCEPT
$IPT -A OUTPUT -p tcp --dport 53  -m conntrack --ctstate NEW -j ACCEPT
$IPT -A OUTPUT -p tcp --dport 853 -m conntrack --ctstate NEW -j ACCEPT   # DoT upstream
$IPT -A OUTPUT -p tcp --dport 443 -m conntrack --ctstate NEW -j ACCEPT
$IPT -A OUTPUT -p tcp --dport 80  -m conntrack --ctstate NEW -j ACCEPT

# Everything else falls to the default DROP.
#
# TODO (added here as you build out):
#  - FORWARD rules that actually route VPN client traffic
#  - Function 4: geoip source-country filtering, e.g.
#      $IPT -A INPUT -p tcp --dport 1723 -m geoip ! --src-cc US -j DROP
#    (requires xtables-addons; verifies IP location, not device location)
