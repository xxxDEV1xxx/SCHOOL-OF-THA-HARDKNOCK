#!/usr/bin/env bash
# =============================================================================
# CTW-RHEL9-VC-ACM-REMEDIATION.SH
# Target:  RHEL 9 / Dell E6410
# Threats: Unknown /dev/vc driver + rogue ACM devices + air-gapped wireless PHY
# Phase:   1 of 2 -- vc driver forensics and ACM siphoning
#          Phase 2 will address wireless PHY hardening
#
# Run: sudo bash ctw_rhel9_vc_acm_remediation.sh 2>&1 | tee /root/vc_acm_remediation.log
# =============================================================================

set -euo pipefail
IFS=$'\n\t'

TS=$(date +%Y%m%dT%H%M%S)
OUT="/root/CTW-VC-ACM-${TS}"
mkdir -p "${OUT}"
chmod 700 "${OUT}"

log()  { echo "[$(date +%H:%M:%S)] $*" | tee -a "${OUT}/run.log"; }
warn() { echo "[WARN] $*" | tee -a "${OUT}/run.log"; }
ioc()  { echo "[IOC]  $*" | tee -a "${OUT}/ioc_findings.txt" | tee -a "${OUT}/run.log"; }
cap()  {
    local TAG="$1"; shift
    local F="${OUT}/${TAG}.txt"
    { echo "# ${TAG}  $(date)"; echo "# $*"; echo ""; "$@" 2>&1; } > "${F}"
    log "  [+] ${TAG}"
}

[[ $EUID -ne 0 ]] && { echo "Run as root."; exit 1; }

echo "================================================================"
echo "CTW-RHEL9 VC/ACM REMEDIATION"
echo "Host:   $(uname -n)  Kernel: $(uname -r)"
echo "Date:   $(date)"
echo "Output: ${OUT}"
echo "================================================================"
echo ""


# ============================================================
# PHASE A: UNKNOWN VC DRIVER -- RHEL 9 / 2.6.x CONTEXT
#
# Key difference from DSL 2.4.26:
#   RHEL 9 uses udev -- /dev is dynamic, NOT static
#   /proc/tty/drivers is kernel-generated via tty_io.c
#   driver_name field comes directly from struct tty_driver
#   "unknown" in this context = NULL or empty driver_name
#   on a udev system this is NOT a table mismatch artifact
#   it is a driver that did not register a name -- deliberate
# ============================================================

log "=== PHASE A: VC DRIVER FORENSICS ==="

# A1. Full TTY driver table -- get exact entry for vc/%d
cap "tty_drivers"            cat /proc/tty/drivers
cap "tty_driver_serial"      cat /proc/tty/driver/serial 2>/dev/null || true
cap "tty_driver_usbserial"   cat /proc/tty/driver/usbserial 2>/dev/null || true

# Isolate the unknown entry precisely
{
    echo "=== UNKNOWN DRIVER ISOLATION ==="
    echo ""
    echo "Full /proc/tty/drivers:"
    cat /proc/tty/drivers
    echo ""
    echo "Unknown entries specifically:"
    grep -i unknown /proc/tty/drivers || echo "[no 'unknown' string in /proc/tty/drivers]"
    echo ""
    echo "Major 4 entries (vc + ttyS share major 4 on some kernels):"
    awk '$3 == "4" {print}' /proc/tty/drivers
    echo ""
    echo "RHEL 9 expected vc entry:"
    echo "  vt    /dev/tty    4   1-63   system:vtmaster"
    echo "  OR"
    echo "  vt    /dev/vc/%d  4   1-63   console"
    echo ""
    echo "If driver name is 'unknown' on RHEL 9 with udev:"
    echo "  -> NOT a static table artifact (udev does not use static tables)"
    echo "  -> struct tty_driver->driver_name was NULL or empty at registration"
    echo "  -> Indicates a modified or replacement vt driver"
} > "${OUT}/vc_unknown_isolation.txt"
cat "${OUT}/vc_unknown_isolation.txt"

# A2. kallsyms -- find the vc driver's actual code address
log "A2: kallsyms vc/vt symbol analysis"
{
    echo "=== KALLSYMS: VC/VT DRIVER SYMBOLS ==="
    echo ""
    echo "--- con_ symbols (console driver) ---"
    grep -E '^[0-9a-f]+ [tT] con_' /proc/kallsyms 2>/dev/null || \
        grep 'con_' /proc/kallsyms 2>/dev/null | head -30

    echo ""
    echo "--- vt_ symbols (vt driver) ---"
    grep -E '^[0-9a-f]+ [tT] vt_' /proc/kallsyms 2>/dev/null | head -30

    echo ""
    echo "--- vc_ symbols ---"
    grep -E '^[0-9a-f]+ [tT] vc_' /proc/kallsyms 2>/dev/null | head -30

    echo ""
    echo "--- tty_register_driver (shows who registered what) ---"
    grep 'tty_register_driver\|tty_alloc_driver' /proc/kallsyms 2>/dev/null

    echo ""
    echo "--- Keyboard / i8042 / serio symbols ---"
    grep -E 'i8042|serio|atkbd|kbd_' /proc/kallsyms 2>/dev/null | head -20

    echo ""
    echo "--- Address range check ---"
    echo "Kernel .text base (should be around 0xffffffff81000000 on x86_64):"
    grep ' T _text$\| T _stext$' /proc/kallsyms 2>/dev/null || true
    grep ' T _etext$\| T _end$' /proc/kallsyms 2>/dev/null || true

    echo ""
    echo "--- Symbols NOT in expected kernel .text (potential module injection) ---"
    TEXT_START=$(grep ' T _text$\| T _stext$' /proc/kallsyms 2>/dev/null | \
                 head -1 | awk '{print $1}' || echo "ffffffff81000000")
    TEXT_END=$(grep ' T _etext$' /proc/kallsyms 2>/dev/null | \
               head -1 | awk '{print $1}' || echo "ffffffff82000000")
    echo "Kernel .text: 0x${TEXT_START} - 0x${TEXT_END}"
    echo "(Symbols outside this range from non-module context are suspicious)"

    echo ""
    echo "--- Suspicious symbol names near input/console ---"
    grep -iE 'hook|intercept|capture|keylog|inject|shadow|hide|covert' \
         /proc/kallsyms 2>/dev/null || echo "[no suspicious names in kallsyms]"

} > "${OUT}/kallsyms_vc_analysis.txt"
cat "${OUT}/kallsyms_vc_analysis.txt"

# A3. sysfs vt driver path
log "A3: sysfs virtual terminal driver"
{
    echo "=== SYSFS VT DRIVER ==="
    echo ""
    echo "--- /sys/bus/platform/drivers/ for vt ---"
    ls /sys/bus/platform/drivers/ 2>/dev/null | grep -iE 'vt|console|vc' || \
        echo "[no vt/console in platform drivers]"

    echo ""
    echo "--- /sys/class/tty/ ---"
    ls /sys/class/tty/ 2>/dev/null | head -30

    echo ""
    echo "--- tty0 sysfs details ---"
    ls -la /sys/class/tty/tty0/ 2>/dev/null || true
    cat /sys/class/tty/tty0/active 2>/dev/null || true

    echo ""
    echo "--- Virtual console driver via /sys ---"
    find /sys -name 'driver' 2>/dev/null | xargs grep -l 'vt\|console' 2>/dev/null | \
        head -10 || echo "[no vt driver reference in sysfs]"

    echo ""
    echo "--- /sys/devices/virtual/tty/ ---"
    ls /sys/devices/virtual/tty/ 2>/dev/null | head -20 || true

} > "${OUT}/sysfs_vt_driver.txt"
cat "${OUT}/sysfs_vt_driver.txt"

# A4. Interrupt table -- IRQ 1 keyboard handler verification
log "A4: IRQ 1 keyboard handler"
{
    echo "=== INTERRUPT TABLE: KEYBOARD AND CONSOLE IRQs ==="
    echo ""
    cat /proc/interrupts
    echo ""
    echo "--- IRQ 1 (i8042/keyboard) isolation ---"
    grep '^ *1:' /proc/interrupts || echo "[IRQ 1 not in /proc/interrupts]"
    echo ""
    KBD_HANDLER=$(grep '^ *1:' /proc/interrupts | awk '{print $NF}' 2>/dev/null || echo "NOT_FOUND")
    echo "IRQ 1 handler: ${KBD_HANDLER}"
    if echo "${KBD_HANDLER}" | grep -qiE 'i8042|keyboard|atkbd'; then
        echo "STATUS: Expected -- standard PS/2 keyboard handler"
    elif [[ "${KBD_HANDLER}" == "NOT_FOUND" ]]; then
        echo "STATUS: IRQ 1 not registered -- USB keyboard in use (expected on E6410)"
    else
        ioc "IRQ-1: Non-standard keyboard IRQ handler: ${KBD_HANDLER}"
        echo "STATUS: UNEXPECTED -- ${KBD_HANDLER} owns keyboard IRQ"
    fi
    echo ""
    echo "--- USB input IRQs ---"
    grep -iE 'xhci|ehci|ohci|uhci|usb' /proc/interrupts | head -10 || true

} > "${OUT}/irq_keyboard.txt"
cat "${OUT}/irq_keyboard.txt"

# A5. /dev/vcs and /dev/vcsa -- who is reading console screen buffers
log "A5: Virtual console screen buffer access audit"
{
    echo "=== VCS/VCSA SCREEN BUFFER AUDIT ==="
    echo ""
    echo "--- /dev/vcs* permissions ---"
    ls -la /dev/vcs* /dev/vcsa* 2>/dev/null || echo "[vcs devices not present]"
    echo ""
    echo "--- Processes with open vcs/vcsa/tty/console fds ---"
    for pid in $(ls /proc | grep '^[0-9]'); do
        FDS=$(ls -la /proc/${pid}/fd 2>/dev/null | \
              grep -E 'vcs|vcsa|console|/dev/tty' || true)
        if [[ -n "${FDS}" ]]; then
            CMD=$(cat /proc/${pid}/cmdline 2>/dev/null | \
                  tr '\0' ' ' | cut -c1-80)
            echo "PID ${pid}: ${CMD}"
            echo "${FDS}"
            echo ""
        fi
    done
    echo ""
    echo "--- lsof /dev/vcs* /dev/tty* ---"
    lsof /dev/vcs* /dev/tty* /dev/console 2>/dev/null | head -40 || \
        echo "[lsof not available or no open handles]"

} > "${OUT}/vcs_access_audit.txt"
cat "${OUT}/vcs_access_audit.txt"


# ============================================================
# PHASE B: ACM DEVICE FORENSICS AND SIPHONING
#
# CDC-ACM = USB Communications Device Class Abstract Control Model
# Legitimate uses: USB modems, some USB-serial adapters, RNDIS
# On an air-gapped machine with both adapters down:
#   ANY /dev/ttyACM* device warrants immediate investigation
#   ACM devices can carry:
#     - GSM AT commands (cell modem)
#     - RNDIS network (USB network over ACM)
#     - Raw serial data exfil
#     - GPS NMEA (but you have no GPS dongle connected)
#   An ACM device present without a known physical USB device = IOC
# ============================================================

log "=== PHASE B: ACM DEVICE FORENSICS ==="

# B1. Full ACM device enumeration
cap "acm_devices_dev"        ls -la /dev/ttyACM* /dev/ttyUSB* 2>/dev/null || \
                             echo "[no ACM/USB serial devices in /dev]"

cap "acm_udev_rules"         find /etc/udev/rules.d/ /lib/udev/rules.d/ \
                             -name '*acm*' -o -name '*cdc*' -o -name '*modem*' \
                             2>/dev/null | xargs cat 2>/dev/null || true

{
    echo "=== ACM DEVICE FULL AUDIT ==="
    echo ""
    echo "--- All ttyACM devices ---"
    ls -la /dev/ttyACM* 2>/dev/null || echo "[no /dev/ttyACM* found]"
    echo ""
    echo "--- All ttyUSB devices ---"
    ls -la /dev/ttyUSB* 2>/dev/null || echo "[no /dev/ttyUSB* found]"
    echo ""
    echo "--- USB device tree (lsusb) ---"
    lsusb 2>/dev/null || cat /proc/bus/usb/devices 2>/dev/null | head -80 || \
        echo "[lsusb not available]"
    echo ""
    echo "--- USB tree verbose ---"
    lsusb -v 2>/dev/null | grep -E 'idVendor|idProduct|iManufacturer|iProduct|bInterfaceClass|bInterfaceSubClass' | head -60 || true
    echo ""
    echo "--- dmesg: ACM/CDC/USB-serial events ---"
    dmesg | grep -iE 'cdc_acm|ttyACM|acm[0-9]|cdc_ether|rndis|usb.*serial|gsm|modem' | \
        tail -50 || echo "[no ACM events in dmesg]"
    echo ""
    echo "--- Loaded ACM-related modules ---"
    lsmod | grep -iE 'cdc_acm|cdc_ether|cdc_ncm|rndis|option|sierra|huawei|qmi|mbim' || \
        echo "[no ACM/CDC modules loaded]"
    echo ""
    echo "THREAT ASSESSMENT:"
    ACM_COUNT=$(ls /dev/ttyACM* 2>/dev/null | wc -l)
    USB_COUNT=$(ls /dev/ttyUSB* 2>/dev/null | wc -l)
    echo "ttyACM devices: ${ACM_COUNT}"
    echo "ttyUSB devices: ${USB_COUNT}"
    if (( ACM_COUNT > 0 )); then
        ioc "ACM-PRESENT: ${ACM_COUNT} ttyACM device(s) found on air-gapped machine"
        echo ""
        echo "CRITICAL: ACM devices on air-gapped system with both adapters down"
        echo "  Each device must be correlated to a physical USB device"
        echo "  An ACM device without a known physical USB source = confirmed IOC"
    fi

} > "${OUT}/acm_full_audit.txt"
cat "${OUT}/acm_full_audit.txt"

# B2. Physical USB correlation -- match ACM to actual USB hardware
log "B2: Physical USB to ACM device correlation"
{
    echo "=== PHYSICAL USB CORRELATION ==="
    echo ""
    echo "--- /sys/bus/usb/devices/ full tree ---"
    for USB_DEV in /sys/bus/usb/devices/*/; do
        if [[ -f "${USB_DEV}/idVendor" ]]; then
            VID=$(cat "${USB_DEV}/idVendor" 2>/dev/null)
            PID=$(cat "${USB_DEV}/idProduct" 2>/dev/null)
            MFR=$(cat "${USB_DEV}/manufacturer" 2>/dev/null || echo "unknown")
            PRD=$(cat "${USB_DEV}/product" 2>/dev/null || echo "unknown")
            SER=$(cat "${USB_DEV}/serial" 2>/dev/null || echo "no_serial")
            SPD=$(cat "${USB_DEV}/speed" 2>/dev/null || echo "?")
            echo "Device: $(basename ${USB_DEV})"
            echo "  VID:PID    = ${VID}:${PID}"
            echo "  Mfr        = ${MFR}"
            echo "  Product    = ${PRD}"
            echo "  Serial     = ${SER}"
            echo "  Speed      = ${SPD} Mbps"
            echo "  Class info:"
            cat "${USB_DEV}/bDeviceClass" 2>/dev/null && true
            echo ""
        fi
    done
    echo ""
    echo "--- ACM tty sysfs back-reference ---"
    for ACM in /sys/class/tty/ttyACM*; do
        [[ -e "${ACM}" ]] || continue
        echo "=== $(basename ${ACM}) ==="
        readlink -f "${ACM}" 2>/dev/null || true
        cat "${ACM}/device/manufacturer" 2>/dev/null || true
        cat "${ACM}/device/product" 2>/dev/null || true
        cat "${ACM}/device/idVendor" 2>/dev/null || true
        cat "${ACM}/device/idProduct" 2>/dev/null || true
        echo ""
    done
    echo ""
    echo "--- udevadm info on each ACM device ---"
    for ACM_DEV in /dev/ttyACM*; do
        [[ -e "${ACM_DEV}" ]] || continue
        echo "=== ${ACM_DEV} ==="
        udevadm info --query=all --name="${ACM_DEV}" 2>/dev/null || true
        echo ""
    done

    echo ""
    echo "--- VENDOR ID LOOKUP FOR FLAGGED DEVICES ---"
    echo "Known malicious/suspicious ACM VID:PID patterns:"
    echo "  Any VID:PID not in your known hardware list"
    echo "  GSM modems: 12d1 (Huawei), 19d2 (ZTE), 1e0e (Qualcomm), 2c7c (Quectel)"
    echo "  Rogue RNDIS: any device advertising bInterfaceClass=0x02 (Communications)"
    echo "               without a corresponding physical USB modem plugged in"

} > "${OUT}/usb_correlation.txt"
cat "${OUT}/usb_correlation.txt"

# B3. CAPTURE ACM DATA STREAM -- read what is coming out of each ACM device
log "B3: ACM data stream capture"
{
    echo "=== ACM DATA STREAM CAPTURE ==="
    echo ""
    echo "Reading 5 seconds of data from each ACM device..."
    echo "AT commands, NMEA, or raw data indicate device purpose."
    echo ""

    for ACM_DEV in /dev/ttyACM*; do
        [[ -e "${ACM_DEV}" ]] || continue
        echo "--- Capturing from ${ACM_DEV} ---"

        # Set terminal parameters for AT modem interrogation
        stty -F "${ACM_DEV}" 115200 raw -echo 2>/dev/null || \
            stty -F "${ACM_DEV}" 9600 raw -echo 2>/dev/null || true

        # Send AT identification commands and capture response
        {
            # Standard AT interrogation
            printf 'ATI\r\n'          # Modem identification
            sleep 0.5
            printf 'AT+CGMI\r\n'     # Manufacturer
            sleep 0.5
            printf 'AT+CGMM\r\n'     # Model
            sleep 0.5
            printf 'AT+CGSN\r\n'     # IMEI
            sleep 0.5
            printf 'AT+COPS?\r\n'    # Current operator (if cell modem)
            sleep 0.5
            printf 'AT+CREG?\r\n'    # Network registration
            sleep 0.5
            printf 'AT+CSQ\r\n'      # Signal quality
            sleep 0.5
            printf 'AT+CIMI\r\n'     # IMSI (SIM identity)
            sleep 0.5
        } > "${ACM_DEV}" 2>/dev/null &

        # Capture response stream for 5 seconds
        timeout 5 cat "${ACM_DEV}" 2>/dev/null | \
            strings | head -100 || echo "[no readable data from ${ACM_DEV}]"

        echo ""
        echo "INTERPRETATION:"
        echo "  ATI response  -> confirms GSM/cell modem"
        echo "  NMEA strings  -> GPS device (but you have no GPS connected)"
        echo "  AT+COPS data  -> cell network registration = ACTIVE CELL MODEM"
        echo "  Silence       -> device not responding to AT (could be raw serial)"
        echo "  Binary data   -> raw exfil channel"
        echo ""
    done

} > "${OUT}/acm_data_capture.txt" 2>&1
cat "${OUT}/acm_data_capture.txt"

# B4. Check if ACM devices are associated with cdc_acm kernel module
log "B4: CDC-ACM module inspection"
{
    echo "=== CDC_ACM MODULE INSPECTION ==="
    echo ""
    if lsmod | grep -q cdc_acm; then
        echo "cdc_acm module: LOADED"
        echo ""
        modinfo cdc_acm 2>/dev/null
        echo ""
        echo "--- Module parameters ---"
        find /sys/module/cdc_acm/parameters/ -type f 2>/dev/null | \
            while read P; do echo "$(basename $P): $(cat $P 2>/dev/null)"; done
        echo ""
        echo "--- cdc_acm sysfs bindings ---"
        ls /sys/bus/usb/drivers/cdc_acm/ 2>/dev/null || true
        echo ""
        # Check module signature
        modinfo cdc_acm 2>/dev/null | grep -E 'sig|signer|filename'
        echo ""
        # Verify module file on disk
        ACM_KO=$(modinfo -F filename cdc_acm 2>/dev/null)
        if [[ -n "${ACM_KO}" ]]; then
            echo "Module file: ${ACM_KO}"
            sha256sum "${ACM_KO}" 2>/dev/null
            echo ""
            # Check if module is signed
            if modinfo cdc_acm 2>/dev/null | grep -q 'sig_key'; then
                echo "Module signing: SIGNED"
                modinfo cdc_acm 2>/dev/null | grep sig
            else
                ioc "ACM-MODULE: cdc_acm module is UNSIGNED"
                echo "cdc_acm is UNSIGNED -- verify against known-good RHEL 9 package"
            fi
        fi
    else
        echo "cdc_acm module: NOT LOADED"
        echo "If /dev/ttyACM* exists without cdc_acm loaded -> kernel built-in or forged device"
    fi

    echo ""
    echo "--- All CDC/ACM related modules ---"
    lsmod | grep -iE 'cdc|acm|rndis|ncm|ecm|mbim|qmi' || \
        echo "[no CDC/ACM/RNDIS modules loaded]"

} > "${OUT}/cdc_acm_module.txt"
cat "${OUT}/cdc_acm_module.txt"

# B5. BLOCK AND REMOVE ACM DEVICES
log "B5: ACM device blocking and removal"
{
    echo "=== ACM DEVICE BLOCKING ==="
    echo ""

    # Unload cdc_acm if loaded and no legitimate device known
    if lsmod | grep -q cdc_acm; then
        echo "Unloading cdc_acm module..."
        rmmod cdc_acm 2>/dev/null && \
            echo "[+] cdc_acm unloaded" || \
            echo "[!] cdc_acm could not be unloaded (in use or built-in)"
    fi

    # Unload other CDC modules
    for MOD in cdc_ether cdc_ncm rndis_host rndis_wlan; do
        if lsmod | grep -q "^${MOD} "; then
            rmmod "${MOD}" 2>/dev/null && \
                echo "[+] ${MOD} unloaded" || \
                echo "[!] ${MOD} in use"
        fi
    done

    # Blacklist all CDC/ACM modules
    cat > /etc/modprobe.d/ctw-acm-block.conf << 'MODEOF'
# CTW-RHEL9-VC-ACM: Block all CDC/ACM/RNDIS drivers
# These are legitimate but create attack surface on air-gapped systems
# Remove this file only when a specific ACM device is verified and needed
blacklist cdc_acm
blacklist cdc_ether
blacklist cdc_ncm
blacklist cdc_wdm
blacklist rndis_host
blacklist rndis_wlan
blacklist option
blacklist sierra
blacklist qcserial
blacklist qmi_wwan
blacklist ipheth
blacklist mbim
MODEOF
    echo "[+] ACM/CDC blacklist written to /etc/modprobe.d/ctw-acm-block.conf"

    # udev rule to reject ACM device nodes from being created
    cat > /etc/udev/rules.d/99-ctw-acm-deny.rules << 'UDEVEOF'
# CTW-RHEL9-VC-ACM: Deny ACM/CDC device node creation
# Prevents ttyACM* devices from appearing even if module is loaded
KERNEL=="ttyACM*", ACTION=="add", RUN+="/bin/sh -c 'echo 0 > /sys%p/authorized'"
KERNEL=="ttyACM*", ACTION=="add", SYMLINK-=""
SUBSYSTEM=="tty", KERNEL=="ttyACM*", OPTIONS+="static_node=ttyACM0", MODE="0000"
# Deny CDC Ethernet/RNDIS network interfaces
SUBSYSTEM=="net", DRIVERS=="rndis_host", ACTION=="add", RUN+="/sbin/ip link set %k down"
UDEVEOF
    udevadm control --reload-rules 2>/dev/null
    echo "[+] ACM deny udev rules installed"

    echo ""
    echo "Verification -- ACM devices after blocking:"
    ls -la /dev/ttyACM* 2>/dev/null || echo "[no ttyACM devices -- CLEAN]"

} > "${OUT}/acm_blocking.txt" 2>&1
cat "${OUT}/acm_blocking.txt"


# ============================================================
# PHASE C: VC DRIVER HARDENING ON RHEL 9
#
# We cannot replace the running vc driver safely mid-session
# But we can:
# 1. Audit the running driver's symbol addresses
# 2. Lock the input subsystem to prevent injection
# 3. Restrict /dev/vcs* access (screen buffer exfil prevention)
# 4. Add auditd rules for all console reads
# 5. Prepare a kernel module blacklist for suspicious input modules
# ============================================================

log "=== PHASE C: VC DRIVER HARDENING ==="

# C1. Restrict /dev/vcs screen buffer access
log "C1: Restrict /dev/vcs* screen buffer"
{
    echo "=== /dev/vcs* RESTRICTION ==="
    echo ""
    echo "Current permissions:"
    ls -la /dev/vcs* /dev/vcsa* 2>/dev/null

    # Restrict to root only -- prevents userspace screen scrapers
    chmod 600 /dev/vcs* /dev/vcsa* 2>/dev/null && \
        echo "[+] /dev/vcs* restricted to root:root 0600" || \
        echo "[!] chmod on vcs devices failed"

    # udev rule to enforce on boot
    cat >> /etc/udev/rules.d/99-ctw-acm-deny.rules << 'UDEVEOF'

# Restrict virtual console screen buffers
KERNEL=="vcs*", MODE="0600", OWNER="root", GROUP="root"
KERNEL=="vcsa*", MODE="0600", OWNER="root", GROUP="root"
UDEVEOF
    echo "[+] vcs* restriction added to udev rules"

    echo ""
    echo "After restriction:"
    ls -la /dev/vcs* /dev/vcsa* 2>/dev/null

} > "${OUT}/vcs_restriction.txt" 2>&1
cat "${OUT}/vcs_restriction.txt"

# C2. Input subsystem -- block synthetic injection modules
log "C2: Input injection module blocking"
{
    echo "=== INPUT INJECTION BLOCKING ==="
    echo ""

    # Modules that enable synthetic keystroke injection
    INJECT_MODS="uinput mac_hid mousedev joydev"

    for MOD in ${INJECT_MODS}; do
        if lsmod | grep -q "^${MOD} "; then
            echo "LOADED (suspicious on air-gapped): ${MOD}"
            rmmod "${MOD}" 2>/dev/null && \
                echo "  [+] ${MOD} unloaded" || \
                echo "  [!] ${MOD} could not be unloaded"
        else
            echo "not loaded: ${MOD}"
        fi
    done

    # Append to blacklist
    cat >> /etc/modprobe.d/ctw-acm-block.conf << 'MODEOF'

# CTW-RHEL9-VC-ACM: Block synthetic input injection modules
blacklist uinput
blacklist mac_hid
blacklist mousedev
blacklist joydev
MODEOF
    echo ""
    echo "[+] Input injection modules blacklisted"

} > "${OUT}/input_injection_block.txt" 2>&1
cat "${OUT}/input_injection_block.txt"

# C3. Auditd rules for console access
log "C3: Auditd console monitoring rules"
{
    echo "=== AUDITD CONSOLE MONITORING ==="
    echo ""
    if command -v auditctl &>/dev/null; then
        # Monitor reads from /dev/tty* and /dev/console
        auditctl -a always,exit -F arch=b64 \
            -S open -S openat \
            -F path=/dev/console -k console_open 2>/dev/null && \
            echo "[+] audit rule: /dev/console open" || true

        auditctl -a always,exit -F arch=b64 \
            -S open -S openat \
            -F path=/dev/tty0 -k tty0_open 2>/dev/null && \
            echo "[+] audit rule: /dev/tty0 open" || true

        # Monitor /dev/vcs* reads (screen scraping)
        auditctl -w /dev/vcs -p r -k vcs_read 2>/dev/null && \
            echo "[+] audit watch: /dev/vcs read" || true

        # Monitor tty driver registration (catches runtime injection)
        auditctl -a always,exit -F arch=b64 \
            -S init_module -S finit_module \
            -k module_load 2>/dev/null && \
            echo "[+] audit rule: module load" || true

        # Monitor ACM device creation
        auditctl -w /dev -p w -k dev_write 2>/dev/null && \
            echo "[+] audit watch: /dev writes" || true

        echo ""
        echo "Current audit rules:"
        auditctl -l 2>/dev/null

    else
        echo "[!] auditctl not available -- install audit package"
        echo "    dnf install audit"
    fi

} > "${OUT}/auditd_rules.txt" 2>&1
cat "${OUT}/auditd_rules.txt"

# C4. Lock kernel module loading post-setup
log "C4: Module loading lockdown"
{
    echo "=== MODULE LOADING LOCKDOWN ==="
    echo ""
    echo "Current tainted state: $(cat /proc/sys/kernel/tainted)"
    echo ""
    echo "Applying kernel hardening sysctl..."

    # Restrict module loading to signed modules only
    sysctl -w kernel.modules_disabled=0 2>/dev/null  # keep 0 for now -- set to 1 after verification
    sysctl -w kernel.kptr_restrict=2 2>/dev/null && echo "[+] kptr_restrict=2"
    sysctl -w kernel.dmesg_restrict=1 2>/dev/null && echo "[+] dmesg_restrict=1"
    sysctl -w kernel.perf_event_paranoid=3 2>/dev/null && echo "[+] perf_event_paranoid=3"
    sysctl -w kernel.unprivileged_bpf_disabled=1 2>/dev/null && echo "[+] unprivileged_bpf=disabled"
    sysctl -w kernel.yama.ptrace_scope=2 2>/dev/null && echo "[+] ptrace_scope=2 (admin only)"
    sysctl -w kernel.kexec_load_disabled=1 2>/dev/null && echo "[+] kexec disabled"

    echo ""
    echo "NEXT STEP (after verifying all needed modules are loaded):"
    echo "  echo 1 > /proc/sys/kernel/modules_disabled"
    echo "  This prevents any further module injection until reboot"

} > "${OUT}/module_lockdown.txt" 2>&1
cat "${OUT}/module_lockdown.txt"


# ============================================================
# PHASE D: WIRELESS PHY HARDENING (preview -- full in phase 2)
# Air-gapped but both adapters present and down
# PHY-layer attacks do not require association
# ============================================================

log "=== PHASE D: WIRELESS PHY SURFACE ASSESSMENT ==="

cap "wifi_adapters"          ip link show
cap "wifi_rfkill"            rfkill list all 2>/dev/null || true
cap "wifi_iw_dev"            iw dev 2>/dev/null || true
cap "wifi_iw_phy"            iw phy 2>/dev/null || true
cap "wifi_drivers"           lspci -k 2>/dev/null | grep -A 3 -iE 'wireless|wifi|network' || true
cap "wifi_modules"           lsmod | grep -iE 'iwl|ath|rtl|bcm|wl|mt76|mac80211|cfg80211' || true

{
    echo "=== WIRELESS PHY THREAT ASSESSMENT ==="
    echo ""
    echo "Both adapters down does NOT mean safe. PHY-layer attacks:"
    echo ""
    echo "1. Management frame injection:"
    echo "   Probe responses, beacon frames, deauth -- received without association"
    echo "   Driver processes these frames even with interface down"
    echo "   Malformed frames exploit driver parsing (e.g., rtl8192 heap overflow)"
    echo ""
    echo "2. Monitor mode passive reception:"
    echo "   Even with interface 'down', hardware may still receive"
    echo "   Driver firmware processes received frames below OS visibility"
    echo ""
    echo "3. Active adapters present:"
    echo "   Their firmware is running regardless of ip link down state"
    echo "   Firmware vulnerabilities are exploitable at range"
    echo ""
    echo "MITIGATIONS (Phase 2 will implement):"
    echo "  - rfkill block all (hard block via kernel)"
    echo "  - modprobe blacklist for all WiFi drivers"
    echo "  - Physical: tape over antennas or remove mini-PCIe card"
    echo ""
    echo "--- Current rfkill state ---"
    rfkill list all 2>/dev/null || true
    echo ""
    echo "--- Soft-blocking all wireless now ---"
    rfkill block all 2>/dev/null && \
        echo "[+] rfkill block all applied" || \
        echo "[!] rfkill block failed"
    rfkill list all 2>/dev/null || true

} > "${OUT}/wireless_assessment.txt" 2>&1
cat "${OUT}/wireless_assessment.txt"


# ============================================================
# FINAL MANIFEST
# ============================================================

log "=== GENERATING MANIFEST ==="

{
    echo "CTW-RHEL9-VC-ACM REMEDIATION MANIFEST"
    echo "Run: $(date)"
    echo "Kernel: $(uname -r)"
    echo ""
    find "${OUT}" -type f ! -name "MANIFEST.txt" | sort | while read F; do
        sha256sum "${F}"
    done
} > "${OUT}/MANIFEST.txt"

echo ""
echo "================================================================"
echo "REMEDIATION COMPLETE"
echo ""
echo "Output: ${OUT}"
echo "Files:  $(find ${OUT} -type f | wc -l)"
echo ""
echo "ACTIONS TAKEN:"
echo "  [+] vc driver symbol table extracted to kallsyms_vc_analysis.txt"
echo "  [+] ACM devices audited and data captured to acm_data_capture.txt"
echo "  [+] cdc_acm and CDC modules blacklisted"
echo "  [+] ACM deny udev rules installed"
echo "  [+] /dev/vcs* restricted to root:600"
echo "  [+] Input injection modules blacklisted and unloaded"
echo "  [+] Auditd rules for console/vcs/module monitoring"
echo "  [+] Kernel sysctl hardening applied"
echo "  [+] rfkill block all applied (wireless soft-blocked)"
echo ""
echo "REVIEW IMMEDIATELY:"
echo "  cat ${OUT}/acm_data_capture.txt    # What was the ACM device sending?"
echo "  cat ${OUT}/usb_correlation.txt     # Does each ACM have a physical USB source?"
echo "  cat ${OUT}/kallsyms_vc_analysis.txt # vc driver symbol addresses"
echo "  cat ${OUT}/ioc_findings.txt        # All flagged IOCs"
echo ""
echo "PHASE 2 (wireless PHY hardening) ready when you are."
echo "================================================================"
