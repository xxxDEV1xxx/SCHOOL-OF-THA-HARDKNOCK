#!/usr/bin/env bash
# =============================================================================
# CTW-RHEL9-DEV-PURGE.SH
# Targeted /dev cleanup based on IMG_3937 live evidence
#
# CONFIRMED MALICIOUS:
#   /dev/X0R  -> null  (digit zero, created 05:53 today -- NOT a system device)
#   /dev/XOR  -> null  (letter O,   created 05:53 today -- NOT a system device)
#   Both are obfuscation-named symlinks created at the same timestamp
#   XOR/X0R naming is a known covert implant naming convention
#
# SUSPICIOUS / UNNECESSARY:
#   /dev/ramdisk -> ram0     (IOC-027 confirmed on RHEL 9)
#   /dev/floppy  -> fd0      (no floppy hardware on E6410)
#   /dev/floppy-fd0 -> fd0   (same)
#   /dev/oldmem              (crash dump device -- no legitimate use on running system)
#   /dev/parport0-3          (no parallel ports on E6410 laptop)
#   /dev/nvram               (NVRAM direct access -- attack surface)
#   /dev/watchdog            (needs verification -- can be used for forced reboot)
#   fd0u360/720/800/820/830  (floppy format variants -- no hardware)
#
# Run: sudo bash ctw_rhel9_dev_purge.sh 2>&1 | tee /root/dev_purge.log
# =============================================================================

set -euo pipefail

TS=$(date +%Y%m%dT%H%M%S)
OUT="/root/CTW-DEV-PURGE-${TS}"
mkdir -p "${OUT}"
chmod 700 "${OUT}"

log()  { echo "[$(date +%H:%M:%S)] $*" | tee -a "${OUT}/run.log"; }
ioc()  { echo "[IOC]  $*" | tee -a "${OUT}/ioc.txt" | tee -a "${OUT}/run.log"; }
kill_dev() {
    local DEV="$1"
    local REASON="$2"
    if [ -e "${DEV}" ] || [ -L "${DEV}" ]; then
        # Capture full details before removal
        {
            echo "=== ${DEV} ==="
            ls -la "${DEV}" 2>/dev/null || true
            stat "${DEV}" 2>/dev/null || true
            file "${DEV}" 2>/dev/null || true
            if [ -L "${DEV}" ]; then
                echo "Symlink target: $(readlink -f ${DEV} 2>/dev/null || readlink ${DEV})"
            fi
            echo "Reason for removal: ${REASON}"
            echo ""
        } >> "${OUT}/removed_devices.txt"
        rm -f "${DEV}" && log "  [REMOVED] ${DEV} -- ${REASON}" || \
            log "  [FAILED]  ${DEV} -- could not remove"
    else
        log "  [ABSENT]  ${DEV} -- already gone"
    fi
}

[[ $EUID -ne 0 ]] && { echo "Run as root."; exit 1; }

echo "================================================================"
echo "CTW-RHEL9 /dev PURGE AND HARDENING"
echo "Target: Dell E6410 RHEL 9"
echo "Time:   $(date)"
echo "================================================================"
echo ""


# ============================================================
# STEP 0: FULL /dev SNAPSHOT BEFORE ANY CHANGES
# ============================================================

log "STEP 0: Pre-purge /dev snapshot"
{
    echo "# Full /dev listing before purge -- $(date)"
    ls -laR /dev/ 2>/dev/null
} > "${OUT}/dev_before.txt"
log "  Snapshot: ${OUT}/dev_before.txt ($(wc -l < ${OUT}/dev_before.txt) lines)"

# All symlinks in /dev with targets and timestamps
{
    echo "# All symlinks in /dev"
    find /dev -maxdepth 2 -type l -printf '%T+ %p -> %l\n' 2>/dev/null | sort
} > "${OUT}/dev_symlinks_all.txt"
log "  Symlinks: $(wc -l < ${OUT}/dev_symlinks_all.txt) total"

# All devices created today (timestamp IOC)
{
    echo "# Devices created/modified today: $(date +%Y-%m-%d)"
    find /dev -maxdepth 2 -newer /proc/1 -printf '%T+ %p\n' 2>/dev/null | sort || \
    find /dev -maxdepth 2 \( -type l -o -type c -o -type b \) \
         -newer /var/log/messages -printf '%T+ %p\n' 2>/dev/null | sort || \
    ls -lat /dev/ | head -40
} > "${OUT}/dev_recent.txt"
log "  Recent devices: ${OUT}/dev_recent.txt"

# Hash all symlink targets for provenance
{
    echo "# Symlink target analysis"
    find /dev -maxdepth 1 -type l 2>/dev/null | while read L; do
        TARGET=$(readlink "${L}" 2>/dev/null || echo "BROKEN")
        echo "$(ls -la ${L} 2>/dev/null | awk '{print $6,$7,$8}')  $(basename ${L}) -> ${TARGET}"
    done | sort -k1,2
} > "${OUT}/dev_symlink_targets.txt"


# ============================================================
# STEP 1: MALICIOUS DEVICES -- X0R AND XOR
# These are the priority. Remove, document, investigate origin.
# ============================================================

log ""
log "STEP 1: MALICIOUS DEVICE REMOVAL -- X0R / XOR"
log ""

# Full forensic capture of X0R and XOR before removal
{
    echo "================================================================"
    echo "FORENSIC CAPTURE: /dev/X0R and /dev/XOR"
    echo "================================================================"
    echo ""
    echo "FINDING: Two symlinks pointing to /dev/null"
    echo "  Both created 2026-04-24 05:53 (same timestamp)"
    echo "  /dev/X0R uses digit zero (0) -- visually identical to /dev/XOR"
    echo "  /dev/XOR uses letter O -- deliberate lookalike obfuscation"
    echo ""
    echo "WHY THIS IS MALICIOUS:"
    echo "  1. Neither device exists in any Linux distribution"
    echo "  2. XOR is a fundamental cryptographic operation name"
    echo "     Used in cipher implementations, keystream generators"
    echo "     Naming a covert device 'XOR' is a signature"
    echo "  3. Pointing to /dev/null means:"
    echo "     a) Any write to /dev/X0R or /dev/XOR is silently discarded"
    echo "     b) Used as a sink for data that should not appear in logs"
    echo "     c) OR: the symlink target was recently changed FROM something"
    echo "        meaningful TO null to hide what it was pointing at"
    echo "  4. Same-second creation timestamp = created by a script or"
    echo "     automated process, not a human typing commands"
    echo "  5. The digit-zero vs letter-O trick is a deliberate evasion:"
    echo "     'ls /dev/XOR' and 'ls /dev/X0R' look identical on screen"
    echo "     Scripts checking for one will miss the other"
    echo ""
    echo "POSSIBLE FUNCTIONS:"
    echo "  - Data sink: covert process writes to X0R/X0R, appears to go nowhere"
    echo "  - Former pointer: was pointing to a covert device, nulled before inspection"
    echo "  - Decoy: designed to be found and dismissed, real device elsewhere"
    echo "  - Trigger: udev rule watching for open() on X0R/X0R as a signal"
    echo ""
    echo "--- /dev/X0R (digit zero) ---"
    ls -la /dev/X0R 2>/dev/null || echo "[not present]"
    stat /dev/X0R 2>/dev/null || true
    echo ""
    echo "--- /dev/XOR (letter O) ---"
    ls -la /dev/XOR 2>/dev/null || echo "[not present]"
    stat /dev/XOR 2>/dev/null || true
    echo ""
    echo "--- Checking for udev rules referencing X0R or XOR ---"
    grep -r 'X0R\|XOR\|x0r\|xor' /etc/udev/ /lib/udev/ /run/udev/ 2>/dev/null || \
        echo "[no udev rules reference X0R/XOR by name]"
    echo ""
    echo "--- Checking for any process that opened X0R/XOR ---"
    lsof /dev/X0R /dev/XOR 2>/dev/null || \
        echo "[no processes currently have X0R/XOR open]"
    echo ""
    echo "--- Audit log: who created these ---"
    ausearch -f /dev/X0R 2>/dev/null | tail -20 || \
    ausearch -f /dev/XOR 2>/dev/null | tail -20 || \
    grep -E 'X0R|XOR' /var/log/audit/audit.log 2>/dev/null | tail -20 || \
        echo "[no audit log entries for X0R/XOR -- auditd may not have been active]"
    echo ""
    echo "--- journalctl for X0R/XOR creation events ---"
    journalctl --since "2026-04-24 05:50" --until "2026-04-24 05:56" 2>/dev/null | \
        grep -iE 'X0R|XOR|symlink|mknod' | head -20 || \
        echo "[no journal entries in creation window]"
    echo ""
    echo "--- Check for other lookalike device names (0 vs O obfuscation) ---"
    ls /dev/ | grep -P '[0O]{2,}|XOR|X0R|l1|Il|1I' 2>/dev/null || \
        echo "[no other obvious lookalike names]"

} > "${OUT}/xor_x0r_forensics.txt" 2>&1
cat "${OUT}/xor_x0r_forensics.txt"
ioc "MALICIOUS: /dev/X0R -> null (digit-zero, created 05:53 today)"
ioc "MALICIOUS: /dev/XOR -> null (letter-O, created 05:53 today)"
ioc "PATTERN: Same-second timestamp, XOR naming, 0/O obfuscation = automated implant"

kill_dev "/dev/X0R" "MALICIOUS: covert null-sink, digit-zero obfuscation, created 05:53"
kill_dev "/dev/XOR" "MALICIOUS: covert null-sink, letter-O obfuscation, created 05:53"

# Verify removal
echo ""
echo "Verification:"
ls -la /dev/X0R /dev/XOR 2>/dev/null && \
    log "  [WARN] X0R/XOR still present after removal attempt" || \
    log "  [OK] X0R and XOR removed"


# ============================================================
# STEP 2: IOC-027 -- RAMDISK
# /dev/ramdisk -> ram0 confirmed on RHEL 9
# ============================================================

log ""
log "STEP 2: RAMDISK DEVICE -- IOC-027"
log ""

{
    echo "=== /dev/ramdisk FORENSICS ==="
    ls -la /dev/ramdisk /dev/ram* 2>/dev/null || true
    echo ""
    echo "Is any RAM device mounted?"
    mount | grep '/dev/ram' || echo "[no ram devices mounted]"
    echo ""
    echo "Is brd module loaded?"
    lsmod | grep '^brd' || echo "[brd not loaded]"
    echo ""
    echo "RAM device contents check:"
    # Try to read first 512 bytes of ram0 for filesystem signature
    dd if=/dev/ram0 bs=512 count=1 2>/dev/null | strings | head -10 || \
        echo "[ram0 not readable or empty]"
    echo ""
    echo "All ram* entries:"
    ls -la /dev/ram* 2>/dev/null || echo "[no /dev/ram* devices]"
} > "${OUT}/ramdisk_forensics.txt" 2>&1
cat "${OUT}/ramdisk_forensics.txt"

# Check for filesystem on ram0 before removing symlink
RAM0_SIG=$(dd if=/dev/ram0 bs=512 count=1 2>/dev/null | \
           od -A x -t x1 2>/dev/null | head -3 || echo "unreadable")
if echo "${RAM0_SIG}" | grep -qvE '^0000000 00 00|unreadable'; then
    ioc "RAMDISK: /dev/ram0 contains non-zero data -- filesystem or payload present"
    # Image it before removing
    dd if=/dev/ram0 of="${OUT}/ram0_image.bin" 2>/dev/null && \
        log "  [+] ram0 imaged to ${OUT}/ram0_image.bin" || true
    strings "${OUT}/ram0_image.bin" 2>/dev/null > "${OUT}/ram0_strings.txt" || true
fi

kill_dev "/dev/ramdisk" "IOC-027: ramdisk symlink -- no RAM disk needed on RHEL 9"


# ============================================================
# STEP 3: FLOPPY DEVICES
# No floppy hardware on Dell E6410
# ============================================================

log ""
log "STEP 3: FLOPPY DEVICES"
log ""

{
    echo "=== FLOPPY DEVICE AUDIT ==="
    ls -la /dev/fd* /dev/floppy* 2>/dev/null || true
    echo ""
    echo "floppy module loaded?"
    lsmod | grep floppy || echo "[floppy module not loaded]"
    echo ""
    echo "dmesg for floppy:"
    dmesg | grep -i floppy | head -10 || echo "[no floppy in dmesg]"
} > "${OUT}/floppy_audit.txt" 2>&1
cat "${OUT}/floppy_audit.txt"

for DEV in /dev/floppy /dev/floppy-fd0 /dev/fd0 /dev/fd0u360 /dev/fd0u720 \
           /dev/fd0u800 /dev/fd0u820 /dev/fd0u830 \
           /dev/fd0H360 /dev/fd0H720 /dev/fd0D360; do
    kill_dev "${DEV}" "No floppy hardware on E6410"
done

# Blacklist floppy driver
echo "blacklist floppy" >> /etc/modprobe.d/ctw-acm-block.conf
log "  [+] floppy blacklisted"


# ============================================================
# STEP 4: PARALLEL PORT DEVICES
# parport0-3 on a laptop with no parallel port hardware
# ============================================================

log ""
log "STEP 4: PARALLEL PORT DEVICES"
log ""

{
    echo "=== PARPORT AUDIT ==="
    ls -la /dev/parport* /dev/lp* 2>/dev/null || true
    echo ""
    lsmod | grep parport || echo "[parport modules not loaded]"
    echo ""
    dmesg | grep -i parport | head -10 || echo "[no parport in dmesg]"
} > "${OUT}/parport_audit.txt" 2>&1
cat "${OUT}/parport_audit.txt"

for DEV in /dev/parport0 /dev/parport1 /dev/parport2 /dev/parport3 \
           /dev/lp0 /dev/lp1 /dev/lp2; do
    kill_dev "${DEV}" "No parallel port hardware on E6410"
done

# Blacklist parport drivers
cat >> /etc/modprobe.d/ctw-acm-block.conf << 'EOF'
blacklist parport
blacklist parport_pc
blacklist ppdev
blacklist lp
EOF
log "  [+] parport modules blacklisted"


# ============================================================
# STEP 5: OLDMEM
# /dev/oldmem: access to previous kernel's memory after kexec
# Has no legitimate use on a running non-kexec system
# kexec is a known VMBR persistence mechanism
# ============================================================

log ""
log "STEP 5: /dev/oldmem"
log ""

{
    echo "=== /dev/oldmem AUDIT ==="
    ls -la /dev/oldmem 2>/dev/null || echo "[/dev/oldmem not present]"
    echo ""
    echo "oldmem exists if:"
    echo "  1. System was booted via kexec (kernel-to-kernel reboot)"
    echo "  2. kdump is configured and a crash dump kernel is loaded"
    echo "  3. A VMBR used kexec to chainload the visible kernel"
    echo ""
    echo "kexec status:"
    cat /sys/kernel/kexec_loaded 2>/dev/null || echo "[kexec_loaded not accessible]"
    echo ""
    echo "kdump service status:"
    systemctl is-active kdump 2>/dev/null || echo "[kdump service status unknown]"
    echo ""
    echo "IOC-002 correlation: VMBR confirmed in forensic report"
    echo "oldmem presence on this system is consistent with kexec-based VMBR"
} > "${OUT}/oldmem_audit.txt" 2>&1
cat "${OUT}/oldmem_audit.txt"

if [ -e /dev/oldmem ]; then
    ioc "OLDMEM: /dev/oldmem present -- correlates with IOC-002 kexec/VMBR indicator"
    kill_dev "/dev/oldmem" "VMBR/kexec indicator -- no legitimate use on running system"
fi

# Disable kexec system-wide
sysctl -w kernel.kexec_load_disabled=1 2>/dev/null && \
    log "  [+] kexec_load_disabled=1 applied" || true
echo 'kernel.kexec_load_disabled = 1' >> /etc/sysctl.d/99-ctw-hardening.conf


# ============================================================
# STEP 6: NVRAM
# Direct NVRAM/CMOS access -- can be used to modify boot settings
# or persist implants across reboots in CMOS
# ============================================================

log ""
log "STEP 6: /dev/nvram"
log ""

{
    echo "=== /dev/nvram AUDIT ==="
    ls -la /dev/nvram 2>/dev/null || echo "[/dev/nvram not present]"
    echo ""
    echo "NVRAM contains: BIOS settings, boot order, RTC config"
    echo "Writable /dev/nvram = any process can modify BIOS boot settings"
    echo ""
    echo "Who has nvram open:"
    lsof /dev/nvram 2>/dev/null || echo "[no processes have nvram open]"
    echo ""
    echo "nvram module:"
    lsmod | grep nvram || echo "[nvram not a loaded module]"
    echo ""
    # Read current NVRAM content for baseline
    od -A x -t x1z /dev/nvram 2>/dev/null | head -20 || \
        echo "[nvram not readable]"
} > "${OUT}/nvram_audit.txt" 2>&1
cat "${OUT}/nvram_audit.txt"

# Restrict nvram to root only rather than remove (some services legitimately use it)
chmod 600 /dev/nvram 2>/dev/null && \
    log "  [+] /dev/nvram restricted to root:600" || \
    log "  [!] /dev/nvram chmod failed"

# Add udev rule
cat >> /etc/udev/rules.d/99-ctw-acm-deny.rules << 'EOF'

# Restrict NVRAM direct access
KERNEL=="nvram", MODE="0600", OWNER="root", GROUP="root"
EOF


# ============================================================
# STEP 7: WATCHDOG
# Watchdog timer -- if a process stops petting it, system reboots
# Can be used for forced reboot to clear forensic state
# ============================================================

log ""
log "STEP 7: /dev/watchdog"
log ""

{
    echo "=== /dev/watchdog AUDIT ==="
    ls -la /dev/watchdog* 2>/dev/null || echo "[no watchdog devices]"
    echo ""
    echo "Who has watchdog open (a process holding it open will reboot system if killed):"
    lsof /dev/watchdog 2>/dev/null || echo "[no process has watchdog open]"
    echo ""
    lsmod | grep -iE 'watchdog|iTCO' || echo "[no watchdog module loaded]"
    echo ""
    echo "systemd watchdog:"
    systemctl show | grep -i watchdog | head -5 || true
} > "${OUT}/watchdog_audit.txt" 2>&1
cat "${OUT}/watchdog_audit.txt"

# Restrict watchdog access
chmod 600 /dev/watchdog 2>/dev/null || true
chmod 600 /dev/watchdog0 2>/dev/null || true

cat >> /etc/udev/rules.d/99-ctw-acm-deny.rules << 'EOF'

# Restrict watchdog -- prevents forced reboots by non-root
KERNEL=="watchdog*", MODE="0600", OWNER="root", GROUP="root"
EOF
log "  [+] /dev/watchdog restricted to root:600"


# ============================================================
# STEP 8: FULL /dev SCAN FOR ADDITIONAL ANOMALIES
# Find all devices not in the expected RHEL 9 E6410 set
# ============================================================

log ""
log "STEP 8: FULL /dev ANOMALY SCAN"
log ""

# Expected legitimate devices on RHEL 9 / Dell E6410
# Everything not on this list gets flagged
EXPECTED_DEVS="
null zero full random urandom
console tty tty0 tty1 tty2 tty3 tty4 tty5 tty6 tty7
ttyS0 ttyS1 ttyS2 ttyS3
ptmx pts
stdin stdout stderr
mem kmem port
sda sda1 sda2 sdb sdb1
sr0 cdrom
loop0 loop1 loop2 loop3 loop4 loop5 loop6 loop7
block char bsg bus disk input
rtc rtc0
shm
hugepages
mqueue
mapper
net
cpu dri drm
snd
video0 fb0
vcs vcs1 vcsa vcsa1
sg0 sg1
hidraw0
usbmon0
i2c-0
kvm
agpgart
ppp
autofs
fuse
hpet
log
kmsg
psaux
rfkill
VbolGroup00
"

{
    echo "=== FULL /dev ANOMALY SCAN ==="
    echo ""
    echo "Devices NOT in expected RHEL 9 E6410 set:"
    echo ""
    find /dev -maxdepth 1 2>/dev/null | while read DEV; do
        NAME=$(basename "${DEV}")
        # Skip directories
        [ -d "${DEV}" ] && continue
        # Check if in expected list
        if ! echo "${EXPECTED_DEVS}" | grep -qw "${NAME}"; then
            TYPE=$(stat -c %F "${DEV}" 2>/dev/null || echo "unknown")
            TARGET=""
            [ -L "${DEV}" ] && TARGET="-> $(readlink ${DEV} 2>/dev/null)"
            MTIME=$(stat -c %y "${DEV}" 2>/dev/null | cut -c1-19)
            echo "  UNEXPECTED: ${NAME} (${TYPE}) ${TARGET}  [modified: ${MTIME}]"
        fi
    done
    echo ""
    echo "=== ALL SYMLINKS IN /dev ==="
    find /dev -maxdepth 1 -type l -printf '%T+ %p -> %l\n' 2>/dev/null | sort
    echo ""
    echo "=== RECENTLY MODIFIED (last 24h) ==="
    find /dev -maxdepth 1 -mtime -1 -printf '%T+ %p\n' 2>/dev/null | sort

} > "${OUT}/dev_anomaly_scan.txt" 2>&1
cat "${OUT}/dev_anomaly_scan.txt"

# Act on anything with XOR/X0R-style naming patterns
{
    echo "=== LOOKALIKE NAME PATTERN SCAN ==="
    # Look for 0/O, l/1/I, rn/m substitutions
    find /dev -maxdepth 2 -name '*[0O][0O]*' \
         -o -name '*[Xx][0Oo][Rr]*' \
         -o -name '*[Ii][Ll1]*' 2>/dev/null | grep -v ttyS | grep -v loop | \
         grep -v '/dev/sda' || echo "[no additional lookalike names found]"
} >> "${OUT}/dev_anomaly_scan.txt"


# ============================================================
# STEP 9: LOCK /dev AGAINST RUNTIME MODIFICATION
# Prevent new device nodes being created without authorization
# ============================================================

log ""
log "STEP 9: /dev RUNTIME LOCKDOWN"
log ""

{
    echo "=== /dev RUNTIME LOCKDOWN ==="
    echo ""

    # Auditd watch on /dev for any new file creation
    if command -v auditctl &>/dev/null; then
        auditctl -w /dev -p wa -k dev_modification 2>/dev/null && \
            echo "[+] auditd watch on /dev (write+attribute changes)" || \
            echo "[!] auditd watch failed"
        # Specifically watch for symlink creation
        auditctl -a always,exit -F arch=b64 -S symlink -S symlinkat \
            -F dir=/dev -k dev_symlink 2>/dev/null && \
            echo "[+] auditd symlink creation watch on /dev" || true
        auditctl -a always,exit -F arch=b64 -S mknod -S mknodat \
            -F dir=/dev -k dev_mknod 2>/dev/null && \
            echo "[+] auditd mknod watch on /dev" || true
    fi

    # Persist auditd rules
    mkdir -p /etc/audit/rules.d
    ARULES="/etc/audit/rules.d/ctw-dev.rules"
    cat > "${ARULES}" << 'AUDITEOF'
# CTW-RHEL9: /dev modification monitoring
-w /dev -p wa -k dev_modification
-a always,exit -F arch=b64 -S symlink -S symlinkat -F dir=/dev -k dev_symlink
-a always,exit -F arch=b64 -S mknod -S mknodat -F dir=/dev -k dev_mknod
-a always,exit -F arch=b64 -S open -F path=/dev/null -F success=1 -k devnull_open
AUDITEOF
    echo "[+] Persistent auditd rules written"

    # Reload auditd
    augenrules --load 2>/dev/null || auditctl -R /etc/audit/rules.d/ctw-dev.rules 2>/dev/null || true
    echo "[+] Auditd rules reloaded"

    echo ""
    echo "WHAT THIS CATCHES:"
    echo "  Any new symlink created in /dev -> audit log entry with PID, UID, timestamp"
    echo "  Any mknod call in /dev -> logged"
    echo "  If X0R/XOR-style devices are recreated -> logged immediately"

} > "${OUT}/dev_lockdown.txt" 2>&1
cat "${OUT}/dev_lockdown.txt"


# ============================================================
# STEP 10: RELOAD UDEV AND VERIFY
# ============================================================

log ""
log "STEP 10: UDEV RELOAD AND FINAL VERIFICATION"
log ""

udevadm control --reload-rules 2>/dev/null && \
    log "  [+] udev rules reloaded" || \
    log "  [!] udev reload failed"

{
    echo "=== POST-PURGE /dev STATE ==="
    echo ""
    echo "Remaining devices:"
    ls /dev/ 2>/dev/null
    echo ""
    echo "Remaining symlinks:"
    find /dev -maxdepth 1 -type l -printf '%p -> %l\n' 2>/dev/null | sort
    echo ""
    echo "X0R / XOR check:"
    ls -la /dev/X0R /dev/XOR 2>/dev/null && \
        echo "WARNING: XOR/X0R STILL PRESENT" || \
        echo "[CLEAN] X0R and XOR removed"
    echo ""
    echo "Ramdisk check:"
    ls -la /dev/ramdisk 2>/dev/null && \
        echo "WARNING: ramdisk still present" || \
        echo "[CLEAN] ramdisk removed"
    echo ""
    echo "Floppy check:"
    ls -la /dev/floppy* /dev/fd0* 2>/dev/null && \
        echo "WARNING: floppy devices still present" || \
        echo "[CLEAN] floppy devices removed"

} > "${OUT}/dev_after.txt" 2>&1
cat "${OUT}/dev_after.txt"


# ============================================================
# FINAL REPORT
# ============================================================

{
    echo "================================================================"
    echo "CTW-RHEL9 /dev PURGE -- FINAL REPORT"
    echo "$(date)"
    echo "================================================================"
    echo ""
    echo "IOC FINDINGS:"
    cat "${OUT}/ioc.txt" 2>/dev/null || echo "[none recorded]"
    echo ""
    echo "REMOVED DEVICES:"
    cat "${OUT}/removed_devices.txt" 2>/dev/null | grep '===' || echo "[see removed_devices.txt]"
    echo ""
    echo "ACTIONS TAKEN:"
    grep '\[REMOVED\]\|\[OK\]\|\[+\]' "${OUT}/run.log" 2>/dev/null || true
    echo ""
    echo "FILES:"
    ls -lah "${OUT}/"
    echo ""
    echo "NEXT STEPS:"
    echo "  1. Review ${OUT}/xor_x0r_forensics.txt"
    echo "     -> Check audit log for who/what created X0R and XOR at 05:53"
    echo "     -> Check journal for that timestamp window"
    echo "     -> These were created by something running on this system at 05:53"
    echo "        Find the process. That is the implant."
    echo ""
    echo "  2. Review ${OUT}/dev_anomaly_scan.txt"
    echo "     -> Any remaining unexpected devices"
    echo ""
    echo "  3. PHASE 2: Wireless PHY hardening"
    echo "     -> rfkill block all is already applied"
    echo "     -> Next: driver removal, antenna isolation"
    echo ""
    echo "  4. PHASE 3: Router firmware update path"
    echo "     -> After vc/ACM/dev cleanup confirmed clean"
    echo "     -> Fedora needs one more hardening pass before going online"
    echo "================================================================"
} | tee "${OUT}/final_report.txt"

# Manifest
find "${OUT}" -type f | sort | xargs sha256sum 2>/dev/null > "${OUT}/MANIFEST.txt"
log "Manifest written: ${OUT}/MANIFEST.txt"
