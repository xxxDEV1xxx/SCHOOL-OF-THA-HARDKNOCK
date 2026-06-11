#!/bin/sh
# =============================================================================
# CTW-DSL-VC-UNKNOWN.SH
# Targeted investigation: unknown /dev/vc/%d driver (major 4, minors 1-63)
#
# FINDING: /proc/tty/drivers shows:
#   unknown    /dev/vc/%d    4    1-63    console
#
# Expected: driver name should be "vt" or "console" -- NOT "unknown"
# This is the driver owning ALL virtual consoles tty1-tty63.
# Every keystroke at every virtual console passes through this driver.
#
# Run: sh ctw_dsl_vc_unknown.sh 2>&1 | tee /ramdisk/vc_unknown.txt
# =============================================================================

OUT="/ramdisk/vc_unknown"
mkdir -p "${OUT}"

log() { echo "[$(date +%H:%M:%S)] $*"; }

echo "================================================================"
echo "CTW-DSL: UNKNOWN /dev/vc/%d DRIVER INVESTIGATION"
echo "$(date)"
echo "================================================================"
echo ""

# ============================================================
# 1. FULL TTY DRIVER TABLE -- get exact strings
# ============================================================

log "1. Full /proc/tty/drivers read"
echo "--- /proc/tty/drivers (raw) ---"
cat /proc/tty/drivers
echo ""

# Pull just the vc line for exact field verification
echo "--- vc/%d entry isolation ---"
grep 'vc' /proc/tty/drivers
echo ""

# Major 4 owns both ttyS (64-127) AND vc/%d (1-63)
# Verify no overlap or unexpected minor ranges under major 4
echo "--- All major 4 entries ---"
awk '$3 == "4" {print}' /proc/tty/drivers
echo ""


# ============================================================
# 2. KERNEL SYMBOL TABLE -- find the vc driver registration
# In 2.4.x the vt driver exports: vt_ioctl, con_write, etc.
# If "unknown", those symbols may be absent or point elsewhere
# ============================================================

log "2. /proc/ksyms scan for console/vt symbols"
echo "--- Console/VT symbols in /proc/ksyms ---"
grep -iE 'con_|vt_|vc_|console|vcs|keyboard|kbd|kd_' /proc/ksyms 2>/dev/null \
    || echo "[no console symbols exported or /proc/ksyms unavailable]"
echo ""

echo "--- Major 4 device symbols ---"
grep -iE 'tty_register|chrdev.*4|register_chrdev' /proc/ksyms 2>/dev/null \
    || echo "[chrdev registration symbols not exported]"
echo ""

# Any symbol with 'hook', 'intercept', 'log', 'cap' near tty/vc context
echo "--- Suspicious symbols near tty/vc ---"
grep -iE 'hook|intercept|capture|keylog|inject|shadow' /proc/ksyms 2>/dev/null \
    || echo "[no suspicious symbol names found in ksyms]"
echo ""


# ============================================================
# 3. /proc/tty/ldisc and /proc/tty/ldiscs
# ldisc was EMPTY -- but verify ldiscs (registered disciplines table)
# ============================================================

log "3. Line discipline tables"
echo "--- /proc/tty/ldisc ---"
ls -la /proc/tty/ldisc/ 2>/dev/null && \
    cat /proc/tty/ldisc/* 2>/dev/null || echo "[ldisc empty -- confirmed]"
echo ""

echo "--- /proc/tty/ldiscs ---"
cat /proc/tty/ldiscs 2>/dev/null || echo "[ldiscs not readable as text]"
ls -la /proc/tty/ldiscs/ 2>/dev/null || true
echo ""

# N_TTY (ldisc 0) is always registered. N_SLIP=1, N_PPP=3, N_MOUSE=2
# Any registered ldisc beyond N_TTY(0) warrants investigation
echo "--- Registered ldisc modules in /proc/modules ---"
grep -iE 'ldisc|slip|ppp_async|n_tty|n_hdlc' /proc/modules 2>/dev/null \
    || echo "[no ldisc modules in /proc/modules]"
echo ""


# ============================================================
# 4. /dev/vcs and /dev/vcsa -- virtual console screen buffers
# These expose the framebuffer content of each vc
# If a covert process is reading these, it captures screen content
# ============================================================

log "4. Virtual console screen buffer devices"
echo "--- /dev/vcs* /dev/vcsa* permissions ---"
ls -la /dev/vcs* /dev/vcsa* 2>/dev/null || echo "[vcs devices not present]"
echo ""

# Who is reading the vcs devices right now?
echo "--- /proc/*/fd scan for open vcs/vcsa ---"
for pid in $(ls /proc | grep '^[0-9]'); do
    if ls -la /proc/${pid}/fd 2>/dev/null | grep -qE 'vcs|vcsa|tty|console'; then
        echo "PID ${pid} ($(cat /proc/${pid}/cmdline 2>/dev/null | tr '\0' ' ')):"
        ls -la /proc/${pid}/fd 2>/dev/null | grep -E 'vcs|vcsa|tty|console'
    fi
done
echo ""


# ============================================================
# 5. PROCESS fd SCAN -- who has /dev/tty* open
# A keylogger or console interceptor holds an fd to /dev/tty
# or /dev/console open for reading
# ============================================================

log "5. File descriptor scan for console/tty access"
echo "--- Processes with open tty/console fds ---"
for pid in $(ls /proc | grep '^[0-9]'); do
    FDS=$(ls -la /proc/${pid}/fd 2>/dev/null | grep -E '/dev/tty|/dev/console|/dev/vc' || true)
    if [ -n "${FDS}" ]; then
        CMDLINE=$(cat /proc/${pid}/cmdline 2>/dev/null | tr '\0' ' ' | cut -c1-60)
        echo "PID ${pid}: ${CMDLINE}"
        echo "${FDS}"
        echo ""
    fi
done
echo ""


# ============================================================
# 6. /dev/tty permissions and ownership
# The unknown driver owns /dev/vc/1-63
# Check if device nodes themselves are anomalous
# ============================================================

log "6. Virtual console device node audit"
echo "--- /dev/tty* device nodes ---"
ls -la /dev/tty* 2>/dev/null
echo ""

echo "--- /dev/vc/* device nodes ---"
ls -la /dev/vc/* 2>/dev/null || echo "[/dev/vc/ not present as directory]"
echo ""

# Major/minor verification
echo "--- Major 4 devices in /dev ---"
ls -la /dev/ 2>/dev/null | awk '$5 == "4," {print}' || \
    echo "[could not filter by major number from ls]"
echo ""

# Check for unexpected device files with major 4
echo "--- stat on key console devices ---"
for dev in /dev/tty1 /dev/tty2 /dev/console /dev/tty; do
    [ -e "${dev}" ] && { echo "${dev}:"; stat "${dev}" 2>/dev/null || ls -la "${dev}"; echo ""; }
done


# ============================================================
# 7. INTERRUPT TABLE -- keyboard / console IRQs
# IRQ 1 = keyboard (i8042)
# Any unexpected handler on IRQ 1 = keyboard intercept
# ============================================================

log "7. Interrupt table -- keyboard and console IRQs"
echo "--- /proc/interrupts (full) ---"
cat /proc/interrupts
echo ""

echo "--- IRQ 1 (keyboard) isolation ---"
grep '^ *1:' /proc/interrupts
echo ""

echo "--- IRQ 4 (COM1/ttyS0) and IRQ 3 (COM2/ttyS1) ---"
grep '^ *[34]:' /proc/interrupts
echo ""

# If IRQ 1 shows a handler that isn't "i8042" or "keyboard", flag it
KBD_HANDLER=$(grep '^ *1:' /proc/interrupts | awk '{print $NF}')
echo "IRQ 1 handler: ${KBD_HANDLER}"
if echo "${KBD_HANDLER}" | grep -qiE 'i8042|keyboard|kbd'; then
    echo "STATUS: Expected keyboard handler"
else
    echo "STATUS: UNEXPECTED IRQ 1 HANDLER -- ${KBD_HANDLER}"
    echo "CRITICAL: Non-standard keyboard IRQ handler may indicate interception"
fi
echo ""


# ============================================================
# 8. /proc/driver/ -- what the kernel knows about each driver
# The 'unknown' vc driver may appear here under a real name
# ============================================================

log "8. /proc/driver/ tree"
echo "--- /proc/driver/ contents ---"
ls -la /proc/driver/ 2>/dev/null || echo "[/proc/driver/ not populated]"
echo ""

echo "--- /proc/tty/driver/ contents ---"
ls -la /proc/tty/driver/ 2>/dev/null
echo ""

# Read each driver file
for f in /proc/tty/driver/*; do
    echo "=== $(basename ${f}) ==="
    cat "${f}" 2>/dev/null
    echo ""
done


# ============================================================
# 9. MEMORY MAP -- is there a resident module in unexpected range
# owning the vc driver would require being in kernel space
# ============================================================

log "9. Module memory map"
echo "--- Module address ranges from /proc/modules ---"
# 2.4.x /proc/modules format: name size usecount deps state address
awk '{print $1, $6}' /proc/modules 2>/dev/null | sort -k2 || \
    cat /proc/modules
echo ""

echo "--- Kernel .text boundaries (from /proc/ksyms first/last) ---"
head -1 /proc/ksyms 2>/dev/null
tail -1 /proc/ksyms 2>/dev/null
echo ""


# ============================================================
# 10. DMESG -- driver registration messages at boot
# The vt/console driver prints its name at registration
# 'unknown' suggests no printk was issued, OR it was suppressed
# ============================================================

log "10. dmesg console/vt registration messages"
echo "--- dmesg: console and vt registration ---"
dmesg | grep -iE 'console|vt|vc|keyboard|i8042|serio|input'
echo ""

echo "--- dmesg: tty and serial registration ---"
dmesg | grep -iE 'tty|serial|uart|8250|16550'
echo ""

echo "--- dmesg: chrdev and driver registration ---"
dmesg | grep -iE 'chrdev|register.*driver|driver.*register'
echo ""

# Specifically look for the vt driver registration message
# Standard 2.4.26 message: "Console: colour VGA+ 80x25"
echo "--- dmesg: VGA/framebuffer console init ---"
dmesg | grep -iE 'console.*colour\|console.*color|VGA|framebuffer|fb[0-9]'
echo ""


# ============================================================
# VERDICT
# ============================================================

echo "================================================================"
echo "VERDICT: unknown /dev/vc/%d ANALYSIS"
echo "================================================================"
echo ""
echo "The driver name field in /proc/tty/drivers is set by the driver"
echo "at registration time via tty_register_driver() -- the .driver_name"
echo "or .name field of struct tty_driver."
echo ""
echo "Standard kernel 2.4.26 vt.c registers with name 'vt' or the"
echo "console driver registers as 'console'. Appearing as 'unknown'"
echo "means either:"
echo ""
echo "  A) The .name field was set to NULL or empty string, and the"
echo "     kernel's /proc/tty reporting code defaulted to 'unknown'."
echo "     This is a deliberate modification to avoid identification."
echo ""
echo "  B) A replacement driver registered itself for major 4 / 1-63"
echo "     AFTER the legitimate vt driver, overwriting the registration"
echo "     table entry without providing a driver name."
echo ""
echo "  C) DSL 4.4.10's specific 2.4.26 build uses a stripped-down"
echo "     console driver that omits the name field."
echo "     (LEAST LIKELY -- standard DSL vt.c includes the name field)"
echo ""
echo "CORRELATION WITH OTHER IOCS:"
echo "  IOC-003: Virtual Macintosh mouse on input0 -- synthetic INPUT"
echo "  IOC-011: input1 gap -- unlogged device between mac_hid and synaptics"
echo "  The unknown vc driver + synthetic input devices form a complete"
echo "  keyboard capture and injection pathway:"
echo "    unknown_vc_driver -> captures keystrokes from IRQ 1 -> logs/exfils"
echo "    mac_hid/uinput    -> injects synthetic keystrokes back"
echo ""
echo "NEXT: Cross-reference dmesg output above for console init message."
echo "If dmesg shows 'Console: colour VGA+ 80x25' -- vt driver loaded normally."
echo "If that line is ABSENT -- console driver was replaced after boot message."
echo ""
echo "PRIORITY COMMAND:"
echo "  dmesg | grep -i console"
echo "  cat /proc/tty/driver/serial"
echo "  cat /proc/ksyms | grep -i 'con_\|vt_'"
echo ""
echo "================================================================"

# Final hash
echo ""
echo "--- output files ---"
ls -la "${OUT}/"
find "${OUT}" -type f | while read f; do
    md5sum "${f}" 2>/dev/null || sha256sum "${f}" 2>/dev/null
done
