#!/usr/bin/env bash
# =============================================================================
# nethunter_deploy.sh
# Target : Samsung S7 (herolte/SM-G930x) — kali-nethunter-2026.1-herolte-oui-pie-full
# Purpose: 1) Lock down all NetHunter attack-tool services
#          2) Deploy DSL-S-elf, AoA SoftMAC, Sentinel
#
# Requirements on host:
#   adb installed and on PATH
#   USB debugging enabled on device
#   Payload directories set via the VARS block below
# =============================================================================

set -euo pipefail

# ── ANSI colours ─────────────────────────────────────────────────────────────
RED='\033[0;31m'; YEL='\033[1;33m'; GRN='\033[0;32m'; CYA='\033[0;36m'; NC='\033[0m'
info()  { echo -e "${CYA}[INFO]${NC}  $*"; }
ok()    { echo -e "${GRN}[ OK ]${NC}  $*"; }
warn()  { echo -e "${YEL}[WARN]${NC}  $*"; }
die()   { echo -e "${RED}[FAIL]${NC}  $*" >&2; exit 1; }

# ── HOST-SIDE PAYLOAD PATHS (edit before running) ────────────────────────────
AOA_DIR="./aoa_android"          # directory containing your AoA SoftMAC sources
DSL_ELF="./dsl-s.elf"            # path to your compiled DSL-S ELF binary
SENTINEL_PKG="./sentinel.tar.gz" # path to Sentinel archive

# ── DEVICE-SIDE STAGING PATHS ────────────────────────────────────────────────
STAGE="/sdcard/deploy_stage"
AOA_REMOTE="${STAGE}/aoa_android"
DSL_REMOTE="${STAGE}/dsl"
SENTINEL_REMOTE="${STAGE}/sentinel"

# ── NetHunter chroot path (standard NetHunter-full layout) ───────────────────
CHROOT="/data/local/nhsystem/kali-arm64"

# =============================================================================
# 0. PREFLIGHT
# =============================================================================
preflight() {
    info "Running preflight checks…"

    command -v adb &>/dev/null || die "adb not found — install Android Platform Tools."

    # Wait up to 15 s for exactly one authorised device
    local deadline=$(( $(date +%s) + 15 ))
    while true; do
        local count
        count=$(adb devices | awk 'NR>1 && /device$/{c++} END{print c+0}')
        [[ "$count" -eq 1 ]] && break
        [[ $(date +%s) -gt $deadline ]] && die "No authorised ADB device found."
        sleep 1
    done

    adb shell "id" | grep -q "root\|uid=0" || {
        info "Requesting root via 'adb root'…"
        adb root && sleep 2
    }

    adb shell "id" | grep -q "root\|uid=0" || \
        die "Root not available. Enable 'ADB = root' in NetHunter app → Settings."

    # Verify it's the expected device
    local model board
    model=$(adb shell getprop ro.product.model | tr -d '\r')
    board=$(adb shell getprop ro.product.board | tr -d '\r')
    [[ "$model" =~ SM-G930 ]] || warn "Model is '${model}', expected SM-G930x (S7). Proceed with caution."
    [[ "$board" =~ herolte ]]  || warn "Board is '${board}', expected herolte."

    ok "Preflight passed — device: ${model} / ${board}"
}

# =============================================================================
# 1. DISABLE NETHUNTER ATTACK-TOOL SERVICES
# =============================================================================
disable_attack_tools() {
    info "──────────────────────────────────────────────"
    info "PHASE 1 — Disabling NetHunter attack services"
    info "──────────────────────────────────────────────"

    # ── 1a. Stop & disable Android-side NetHunter services ───────────────────
    local NH_SVCS=(
        "NetHunter"                  # main NetHunter app service
        "com.offsec.nethunter"       # package-based reference
    )
    for svc in "${NH_SVCS[@]}"; do
        info "Stopping Android service: ${svc}"
        adb shell "am force-stop ${svc} 2>/dev/null || true"
    done

    # ── 1b. Kill attack-tool daemons running in chroot ───────────────────────
    # These are the common ones that auto-start in the full image
    local DAEMONS=(
        "kismet"       # wireless IDS / sniffer
        "hostapd"      # rogue AP
        "dnsmasq"      # DHCP/DNS (used by rogue AP setups)
        "bettercap"    # MITM framework
        "msfconsole"   # Metasploit
        "msfrpcd"      # Metasploit RPC
        "armitage"     # Metasploit GUI proxy
        "airodump-ng"  # 802.11 capture
        "aireplay-ng"  # deauth/injection
        "airbase-ng"   # soft AP attack
        "wifiphisher"  # phishing AP
        "responder"    # LLMNR/NBT-NS poisoner
        "ettercap"     # LAN MITM
        "nmap"         # active scanner (kill any running scan)
        "hcxdumptool"  # PMKID capture
        "tcpdump"      # raw packet capture
        "wireshark"    # capture (CLI: dumpcap)
        "dumpcap"
        "hydra"        # brute-force
        "medusa"
        "hashcat"
        "john"         # password cracker
        "sqlmap"       # SQL injection tool
        "nikto"        # web scanner
        "beef-xss"     # browser exploitation
        "social-engineer-toolkit"  # SET
    )

    info "Killing attack daemons inside chroot…"
    for daemon in "${DAEMONS[@]}"; do
        adb shell \
            "chroot ${CHROOT} /bin/bash -c 'killall -q ${daemon} 2>/dev/null; true'" \
            2>/dev/null || true
    done

    # ── 1c. Remove attack-tool autostart entries ──────────────────────────────
    info "Disabling chroot autostart scripts for attack tools…"
    local AUTOSTART_DIR="${CHROOT}/etc/nethunter/autostart"
    adb shell "ls ${AUTOSTART_DIR} 2>/dev/null" | tr -d '\r' | while IFS= read -r entry; do
        case "$entry" in
            kismet*|hostapd*|bettercap*|msf*|responder*|wifiphish*|beef*)
                info "  Disabling autostart: ${entry}"
                adb shell \
                    "mv ${AUTOSTART_DIR}/${entry} ${AUTOSTART_DIR}/${entry}.disabled 2>/dev/null || true"
                ;;
        esac
    done

    # ── 1d. Disable monitor-mode auto-bringup on WLAN interfaces ─────────────
    info "Resetting WLAN interfaces to managed mode…"
    adb shell "
        for iface in wlan0 wlan1 wlan2; do
            if ip link show \$iface &>/dev/null 2>&1; then
                iw dev \$iface set type managed 2>/dev/null || true
                ip link set \$iface down 2>/dev/null || true
                ip link set \$iface up   2>/dev/null || true
            fi
        done
    " 2>/dev/null || true

    # ── 1e. Flush any rogue iptables rules from attack sessions ──────────────
    info "Flushing iptables attack chains…"
    adb shell "
        iptables  -F 2>/dev/null || true
        iptables  -X 2>/dev/null || true
        ip6tables -F 2>/dev/null || true
        ip6tables -X 2>/dev/null || true
        iptables  -t nat -F 2>/dev/null || true
    " 2>/dev/null || true

    ok "Attack tools disabled."
}

# =============================================================================
# 2. PREPARE STAGING AREA
# =============================================================================
prepare_stage() {
    info "──────────────────────────────────────────────"
    info "PHASE 2 — Preparing staging area on device"
    info "──────────────────────────────────────────────"

    adb shell "mkdir -p ${STAGE} ${AOA_REMOTE} ${DSL_REMOTE} ${SENTINEL_REMOTE}"
    ok "Staging directories created at ${STAGE}"
}

# =============================================================================
# 3. DEPLOY AoA SOFTMAC
# =============================================================================
deploy_aoa() {
    info "──────────────────────────────────────────────"
    info "PHASE 3 — Deploying AoA SoftMAC"
    info "──────────────────────────────────────────────"

    [[ -d "$AOA_DIR" ]] || die "AoA source directory not found: ${AOA_DIR}"

    # Push entire source tree
    info "Pushing AoA sources → ${AOA_REMOTE}…"
    adb push "${AOA_DIR}/." "${AOA_REMOTE}/"

    # Build inside NetHunter chroot
    info "Building AoA SoftMAC in chroot (ARM64)…"
    adb shell "chroot ${CHROOT} /bin/bash -lc '
        set -e

        cd ${AOA_REMOTE}

        echo \"[AoA] Installing build deps…\"
        apt-get install -y --no-install-recommends \
            build-essential gcc clang make libssl-dev iproute2 \
            >/dev/null 2>&1

        echo \"[AoA] Verifying platform file…\"
        ls softmac_platform_android.c || { echo \"MISSING: softmac_platform_android.c\"; exit 1; }

        echo \"[AoA] Configuring clock source (CLOCK_BOOTTIME for Exynos 8890)…\"
        # Patch any remaining CLOCK_MONOTONIC references that the platform stub
        # missed (belt-and-suspenders — your file should already handle these)
        grep -rl CLOCK_MONOTONIC . \
            --include=\"*.c\" --include=\"*.h\" \
            | grep -v softmac_platform_android.c \
            | xargs -r sed -i \"s/CLOCK_MONOTONIC/CLOCK_BOOTTIME/g\"

        echo \"[AoA] Building…\"
        make -j\$(nproc) ARCH=arm64 CC=gcc CFLAGS=\"-O2 -Wall -DANDROID_PLATFORM\"

        echo \"[AoA] Build complete.\"
        ls -lh softmac 2>/dev/null || ls -lh *.so 2>/dev/null || \
            echo \"[WARN] Expected output binary not found — check your Makefile target name.\"
    '"

    # Install binary to a sane location inside chroot
    info "Installing AoA SoftMAC binary…"
    adb shell "chroot ${CHROOT} /bin/bash -lc '
        set -e
        cd ${AOA_REMOTE}
        install -Dm755 softmac /usr/local/bin/softmac 2>/dev/null || \
        install -Dm755 aoa_softmac /usr/local/bin/aoa_softmac 2>/dev/null || \
            echo \"[WARN] Could not locate built binary — install manually.\"
    '"

    ok "AoA SoftMAC deployed."
}

# =============================================================================
# 4. DEPLOY DSL-S ELF
# =============================================================================
deploy_dsl() {
    info "──────────────────────────────────────────────"
    info "PHASE 4 — Deploying DSL-S ELF"
    info "──────────────────────────────────────────────"

    [[ -f "$DSL_ELF" ]] || die "DSL-S ELF not found: ${DSL_ELF}"

    info "Pushing DSL-S ELF…"
    adb push "${DSL_ELF}" "${DSL_REMOTE}/dsl-s.elf"
    adb shell "chmod 755 ${DSL_REMOTE}/dsl-s.elf"

    # ── TODO: Fill in your DSL-S install / config steps below ────────────────
    # Example skeleton — replace with actual commands:
    #
    # adb shell "chroot ${CHROOT} /bin/bash -lc '
    #     cp ${DSL_REMOTE}/dsl-s.elf /usr/local/bin/dsl-s
    #     chmod 755 /usr/local/bin/dsl-s
    #     # any config file drops, service registration, etc.
    # '"
    # ─────────────────────────────────────────────────────────────────────────

    warn "DSL-S deploy stub — add your install commands in the TODO block above."
    ok "DSL-S ELF staged at ${DSL_REMOTE}/dsl-s.elf"
}

# =============================================================================
# 5. DEPLOY SENTINEL
# =============================================================================
deploy_sentinel() {
    info "──────────────────────────────────────────────"
    info "PHASE 5 — Deploying Sentinel"
    info "──────────────────────────────────────────────"

    [[ -f "$SENTINEL_PKG" ]] || die "Sentinel package not found: ${SENTINEL_PKG}"

    info "Pushing Sentinel archive…"
    adb push "${SENTINEL_PKG}" "${SENTINEL_REMOTE}/sentinel.tar.gz"

    info "Extracting and installing Sentinel in chroot…"
    adb shell "chroot ${CHROOT} /bin/bash -lc '
        set -e
        cd ${SENTINEL_REMOTE}
        tar -xzf sentinel.tar.gz
        # ── TODO: Replace the line below with your actual Sentinel installer ──
        # e.g.:  bash install.sh  or  make install
        echo \"[TODO] Run your Sentinel install command here.\"
    '"

    # ── TODO: Sentinel service / autostart registration ──────────────────────
    # Example:
    # adb shell "chroot ${CHROOT} /bin/bash -lc '
    #     install -Dm644 ${SENTINEL_REMOTE}/sentinel.service \
    #         /etc/systemd/system/sentinel.service
    #     systemctl enable sentinel
    #     systemctl start  sentinel
    # '"
    # ─────────────────────────────────────────────────────────────────────────

    warn "Sentinel deploy stub — add your install commands in the TODO blocks above."
    ok "Sentinel staged at ${SENTINEL_REMOTE}"
}

# =============================================================================
# 6. POST-DEPLOY VERIFICATION
# =============================================================================
verify() {
    info "──────────────────────────────────────────────"
    info "PHASE 6 — Post-deploy verification"
    info "──────────────────────────────────────────────"

    echo ""
    info "Checking AoA SoftMAC binary…"
    adb shell "chroot ${CHROOT} which softmac 2>/dev/null || \
               chroot ${CHROOT} which aoa_softmac 2>/dev/null || \
               echo '  [!] AoA binary not in PATH — check build output'" 2>/dev/null

    info "Checking DSL-S ELF…"
    adb shell "ls -lh ${DSL_REMOTE}/dsl-s.elf 2>/dev/null || echo '  [!] DSL-S not found'"

    info "Checking Sentinel…"
    adb shell "ls -lh ${SENTINEL_REMOTE}/ 2>/dev/null | head -5"

    info "Confirming attack daemons are NOT running…"
    local still_running=0
    for daemon in kismet hostapd bettercap msfconsole responder; do
        if adb shell "pgrep -x ${daemon}" &>/dev/null; then
            warn "  ${daemon} is still running!"
            still_running=1
        fi
    done
    [[ $still_running -eq 0 ]] && ok "No attack daemons detected."

    info "TUN device check (required by AoA SoftMAC)…"
    adb shell "
        for tun in /dev/tun /dev/net/tun /dev/tun0; do
            [ -e \$tun ] && echo \"  Found: \$tun\" && break
        done
    " 2>/dev/null || warn "No TUN device found — AoA SoftMAC will fail to open tunnel."

    echo ""
    ok "══════════════════════════════════════════════"
    ok " Deploy complete. Review any [WARN] items above."
    ok "══════════════════════════════════════════════"
}

# =============================================================================
# MAIN
# =============================================================================
main() {
    echo ""
    echo -e "${CYA}╔══════════════════════════════════════════════════╗${NC}"
    echo -e "${CYA}║  NetHunter Lockdown + Custom Tool Deploy         ║${NC}"
    echo -e "${CYA}║  Target: S7 herolte — kali-nethunter-2026.1      ║${NC}"
    echo -e "${CYA}╚══════════════════════════════════════════════════╝${NC}"
    echo ""

    preflight
    disable_attack_tools
    prepare_stage
    deploy_aoa
    deploy_dsl
    deploy_sentinel
    verify
}

main "$@"
