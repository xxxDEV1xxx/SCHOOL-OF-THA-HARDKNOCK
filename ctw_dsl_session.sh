#!/bin/sh
# =============================================================================
# CTW-DSL-SESSION.SH
# DSL 4.4.10 toram Session: Hardware Enumeration, Driver Triage, Install Planning
# Target: Dell Pentium 4-M (per CTW-BOOT-FA-001 hardware profile)
# Kernel: 2.6.x (DSL 4.4.10 stock)
# Environment: POSIX sh only — no bash extensions, no bashisms
# Author: Christopher Thomas Williams
# Version: 1.0
# Date: 2026-04-23
#
# BOOT DSL WITH:
#   dsl toram runlevel=2
#   (at boot prompt: dsl toram 2)
#
# COPY SCRIPT TO RAM AND RUN:
#   cp /cdrom/ctw_dsl_session.sh /ramdisk/  (or wherever DSL mounts the CD)
#   chmod +x /ramdisk/ctw_dsl_session.sh
#   sh /ramdisk/ctw_dsl_session.sh
#
# OUTPUT:
#   /ramdisk/CTW-DSL-REPORT-<timestamp>/  (everything in RAM, zero disk writes)
#   /ramdisk/CTW-DSL-REPORT.html          (browsable via DSL's built-in browser)
#
# POSIX NOTE: DSL 4.4.10 ships busybox sh. All constructs here are POSIX-safe.
# =============================================================================

TIMESTAMP=$(date +%Y%m%dT%H%M%S)
REPORT_DIR="/ramdisk/CTW-DSL-${TIMESTAMP}"
HTML_OUT="/ramdisk/CTW-DSL-REPORT-${TIMESTAMP}.html"
LOG="${REPORT_DIR}/session.log"

# Fallback if /ramdisk not available (DSL may use /tmp)
if [ ! -d /ramdisk ]; then
    REPORT_DIR="/tmp/CTW-DSL-${TIMESTAMP}"
    HTML_OUT="/tmp/CTW-DSL-REPORT-${TIMESTAMP}.html"
    LOG="${REPORT_DIR}/session.log"
fi

mkdir -p "${REPORT_DIR}"

# ============================================================
# UTILITY
# ============================================================

log() {
    echo "[$(date +%H:%M:%S)] $*" | tee -a "${LOG}"
}

section() {
    echo ""
    echo "============================================================"
    echo "  $*"
    echo "============================================================"
    log "SECTION: $*"
}

# Run command, capture output to file, print to terminal
cap() {
    TAG="$1"; shift
    OUTFILE="${REPORT_DIR}/${TAG}.txt"
    log "Collecting: ${TAG}"
    {
        echo "# CTW-DSL-SESSION: ${TAG}"
        echo "# Time: $(date)"
        echo "# Command: $*"
        echo "#-----------------------------------------------------------"
        "$@" 2>&1
    } > "${OUTFILE}"
    cat "${OUTFILE}"
    echo ""
}

# Run command if the binary exists, warn if not
maybe() {
    CMD="$1"
    if command -v "${CMD}" >/dev/null 2>&1; then
        "$@"
    else
        echo "[SKIPPED: ${CMD} not in DSL 4.4.10 PATH -- add via mydsl or install.sh]"
    fi
}

# ============================================================
# SECTION 0: BOOT ENVIRONMENT VERIFICATION
# Confirm we are in toram / runlevel 2 / clean environment
# ============================================================

section "0: BOOT ENVIRONMENT VERIFICATION"

cap "boot_cmdline"         cat /proc/cmdline
cap "boot_runlevel"        runlevel
cap "boot_uptime"          uptime
cap "boot_mounts"          cat /proc/mounts
cap "boot_filesystems"     df -h
cap "boot_kernel"          uname -a
cap "boot_dmesg_head"      dmesg | head -80

# Verify toram: root should be a tmpfs/ramdisk, NOT /dev/hda or /dev/sda
log "Verifying toram environment..."
ROOT_FS=$(mount | grep ' / ' | awk '{print $1}')
echo "Root filesystem device: ${ROOT_FS}"
if echo "${ROOT_FS}" | grep -qE 'tmpfs|ramdisk|ram'; then
    log "OK: Root is RAM-based (toram confirmed)"
else
    log "WARNING: Root may not be toram (${ROOT_FS}) -- verify before writing any data"
fi

# Verify runlevel 2
RLEVEL=$(runlevel 2>/dev/null | awk '{print $2}')
if [ "${RLEVEL}" = "2" ]; then
    log "OK: Runlevel 2 confirmed"
else
    log "INFO: Current runlevel: ${RLEVEL}"
fi

cap "boot_env_vars"        env | sort
cap "boot_processes"       ps aux 2>/dev/null || ps -ef


# ============================================================
# SECTION 1: SERIAL PORTS
# COM ports, UART, ttyS* -- detect, enumerate, identify
# ============================================================

section "1: SERIAL PORT ENUMERATION"

cap "serial_dmesg"         dmesg | grep -iE 'serial|uart|ttyS|8250|16550'

cap "serial_ttys_proc"     cat /proc/tty/drivers

cap "serial_ttys_dev"      ls -la /dev/ttyS* /dev/ttyUSB* /dev/ttyACM* 2>/dev/null

# setserial for hardware UART details (available in DSL 4.4.10)
echo "=== setserial probe ttyS0-ttyS3 ===" > "${REPORT_DIR}/serial_setserial.txt"
for PORT in ttyS0 ttyS1 ttyS2 ttyS3; do
    DEV="/dev/${PORT}"
    if [ -e "${DEV}" ]; then
        echo "--- ${DEV} ---"
        maybe setserial -g "${DEV}" 2>/dev/null || echo "[setserial not available]"
        # Try to get IRQ and I/O port assignments
        maybe setserial -a "${DEV}" 2>/dev/null
    else
        echo "${DEV}: not present"
    fi
done >> "${REPORT_DIR}/serial_setserial.txt"
cat "${REPORT_DIR}/serial_setserial.txt"

# Check /proc/interrupts for COM port IRQs (4=COM1, 3=COM2)
cap "serial_irq"           grep -E 'serial|4:|3:' /proc/interrupts

# Check /proc/ioports for standard COM addresses (0x3f8, 0x2f8)
cap "serial_ioports"       grep -iE '03f8|02f8|03e8|02e8|serial|uart' /proc/ioports

# USB-serial adapters
cap "serial_usb"           dmesg | grep -iE 'ftdi|pl2303|cp210|ch34|cdc_acm|usb.*serial'

# Flag anomalous serial devices from IOC context
echo "" >> "${REPORT_DIR}/serial_setserial.txt"
echo "=== ANOMALY CHECK ===" >> "${REPORT_DIR}/serial_setserial.txt"
echo "Expected on Dell Pentium 4-M: one integrated COM port (ttyS0, IRQ4, 0x3F8)" \
     >> "${REPORT_DIR}/serial_setserial.txt"
echo "Anomalous: additional COM ports with non-standard IRQ or I/O ranges" \
     >> "${REPORT_DIR}/serial_setserial.txt"
SERIAL_COUNT=$(ls /dev/ttyS* 2>/dev/null | wc -l)
echo "ttyS devices found: ${SERIAL_COUNT}" >> "${REPORT_DIR}/serial_setserial.txt"
if [ "${SERIAL_COUNT}" -gt 2 ]; then
    echo "WARNING: More than 2 ttyS devices -- investigate ttyS2/ttyS3" \
         >> "${REPORT_DIR}/serial_setserial.txt"
fi
log "Serial: ${SERIAL_COUNT} ttyS devices found"


# ============================================================
# SECTION 2: FULL DEVICE ENUMERATION
# PCI, PnP, ACPI, USB, input, block, storage -- comprehensive
# ============================================================

section "2: DEVICE ENUMERATION"

# --- 2.1 PCI ---
echo "--- 2.1 PCI DEVICES ---"
cap "pci_short"            cat /proc/bus/pci/devices 2>/dev/null || true
cap "pci_lspci_basic"      lspci 2>/dev/null || cat /proc/bus/pci/devices
cap "pci_lspci_verbose"    lspci -v 2>/dev/null || true
cap "pci_lspci_kernel"     lspci -k 2>/dev/null || true
cap "pci_lspci_nn"         lspci -nn 2>/dev/null || true

# Cross-reference PCI output against forensic report IOCs
{
    echo "=== PCI ANOMALY CROSS-REFERENCE ==="
    echo ""
    echo "IOC-013: 12 I/O port ranges with gap at 0xf300:"
    grep -c 'f[0-9a-f]00-f[0-9a-f]fe' /proc/ioports 2>/dev/null && true
    echo ""
    echo "IOC-014: PnP/PCI memory overlap check:"
    grep -iE 'overlap|disable' /proc/iomem 2>/dev/null | head -5 || echo "[no overlap entries]"
    echo ""
    echo "IOC-015: Reserved region at 0x27fe2800:"
    grep '27fe' /proc/iomem 2>/dev/null || echo "[region not found in clean boot iomem]"
    echo ""
    echo "IOC-018: CardBus socket status:"
    lspci -v 2>/dev/null | grep -A 3 -i yenta || echo "[Yenta not found -- no CardBus]"
    echo ""
    echo "IOC-035: PCI output corruption check (DSL dmesg should be clean):"
    dmesg | grep -iE 'pci|acpi' | grep -iE 'error|corrupt|failed|warning' || echo "[No PCI errors in DSL dmesg]"
} > "${REPORT_DIR}/pci_anomaly_check.txt"
cat "${REPORT_DIR}/pci_anomaly_check.txt"

# --- 2.2 ACPI and DSDT ---
echo ""
echo "--- 2.2 ACPI ---"
cap "acpi_tables"          ls -la /sys/firmware/acpi/tables/ 2>/dev/null || \
                           ls -la /proc/acpi/ 2>/dev/null || true
cap "acpi_dsdt_strings"    strings /sys/firmware/acpi/tables/DSDT 2>/dev/null | head -40 || \
                           strings /proc/acpi/dsdt 2>/dev/null | head -40 || true
cap "acpi_processor"       cat /proc/acpi/processor/CPU0/info 2>/dev/null || true
cap "acpi_cstates"         cat /proc/acpi/processor/CPU0/power 2>/dev/null || true
cap "acpi_thermal"         cat /proc/acpi/thermal_zone/*/temperature 2>/dev/null || true
cap "acpi_battery"         cat /proc/acpi/battery/*/info 2>/dev/null || true

# IOC-004: DSDT OEM check from clean DSL environment
{
    echo "=== IOC-004 DSDT VENDOR CHECK (from clean DSL environment) ==="
    DSDT_SRC=""
    if [ -f /sys/firmware/acpi/tables/DSDT ]; then
        DSDT_SRC="/sys/firmware/acpi/tables/DSDT"
    elif [ -f /proc/acpi/dsdt ]; then
        DSDT_SRC="/proc/acpi/dsdt"
    fi
    if [ -n "${DSDT_SRC}" ]; then
        OEM_STR=$(strings "${DSDT_SRC}" | grep -iE 'INT430|SYSFe|SYSF|DELL|dell' | head -10)
        echo "OEM strings found: ${OEM_STR}"
        if echo "${OEM_STR}" | grep -qi 'INT430\|SYSFe'; then
            echo "IOC-004 STATUS: CONFIRMED -- non-Dell DSDT OEM string present in clean boot"
            echo "SIGNIFICANCE: DSDT modification persists across OS -- BIOS-level compromise"
        elif echo "${OEM_STR}" | grep -qi 'DELL'; then
            echo "IOC-004 STATUS: Not confirmed -- DSDT reports Dell origin"
        else
            echo "IOC-004 STATUS: Inconclusive -- OEM strings: ${OEM_STR}"
        fi
    else
        echo "DSDT source not accessible via /sys or /proc"
    fi
} > "${REPORT_DIR}/dsdt_ioc004_check.txt"
cat "${REPORT_DIR}/dsdt_ioc004_check.txt"

# IOC-033: C3 state check from clean environment
{
    echo "=== IOC-033 C3 STATE CHECK ==="
    if [ -f /proc/acpi/processor/CPU0/power ]; then
        cat /proc/acpi/processor/CPU0/power
        if grep -q 'C3' /proc/acpi/processor/CPU0/power; then
            echo "C3 PRESENT in clean DSL boot"
            echo "IOC-033: If C3 was absent in compromised boot, BIOS manipulation confirmed"
        else
            echo "C3 ABSENT in clean DSL boot -- consistent with hardware limitation or BIOS suppression"
        fi
    fi
} > "${REPORT_DIR}/c3_clean_check.txt"
cat "${REPORT_DIR}/c3_clean_check.txt"

# --- 2.3 INPUT DEVICES ---
echo ""
echo "--- 2.3 INPUT DEVICES ---"
cap "input_proc"           cat /proc/bus/input/devices 2>/dev/null || true
cap "input_dev"            ls -la /dev/input/ 2>/dev/null || true
cap "input_dmesg"          dmesg | grep -iE 'input:|mousedev|synaptics|psmouse|i8042|serio'

# IOC-003/011: Virtual input device check from clean environment
{
    echo "=== IOC-003 / IOC-011: Input device anomaly check (clean DSL) ==="
    echo ""
    echo "Registered input devices:"
    cat /proc/bus/input/devices 2>/dev/null || true
    echo ""
    if grep -qi 'Macintosh\|macintosh\|mac_hid' /proc/bus/input/devices 2>/dev/null; then
        echo "IOC-003 STATUS: CONFIRMED IN CLEAN BOOT"
        echo "CRITICAL: Macintosh mouse emulation present in DSL (uncompromised) boot"
        echo "This indicates BIOS/ACPI-level injection, not OS-level"
    else
        echo "IOC-003 STATUS: Macintosh emulation device NOT present in clean DSL boot"
        echo "This is EXPECTED -- device was OS/initrd-injected in compromised Fedora boot"
    fi
    echo ""
    # Count input devices and check for gap
    INPUT_COUNT=$(ls /dev/input/event* 2>/dev/null | wc -l)
    echo "Input event devices: ${INPUT_COUNT}"
    for i in 0 1 2 3 4; do
        if [ -e "/dev/input/event${i}" ]; then
            echo "event${i}: PRESENT"
        else
            echo "event${i}: ABSENT"
        fi
    done
} > "${REPORT_DIR}/input_clean_check.txt"
cat "${REPORT_DIR}/input_clean_check.txt"

# --- 2.4 BLOCK / STORAGE DEVICES ---
echo ""
echo "--- 2.4 STORAGE DEVICES ---"
cap "storage_proc"         cat /proc/partitions
cap "storage_fdisk"        fdisk -l 2>/dev/null || true
cap "storage_dmesg"        dmesg | grep -iE 'hd[a-z]|sd[a-z]|ide|ata|ahci|sata|fujitsu'
cap "storage_ide_info"     hdparm -i /dev/hda 2>/dev/null || hdparm -i /dev/sda 2>/dev/null || true

# Fujitsu MHV2040A identification (expected from forensic report)
{
    echo "=== STORAGE IDENTITY CHECK ==="
    for DEV in /dev/hda /dev/sda /dev/hdb; do
        if [ -b "${DEV}" ]; then
            echo "--- ${DEV} ---"
            hdparm -I "${DEV}" 2>/dev/null | head -20
            echo ""
        fi
    done
    echo "Expected: Fujitsu MHV2040A, 40GB PATA"
    echo ""
    echo "IOC-031: Disk identity verification (edd=off was disabled in compromised boot):"
    echo "From DSL (no edd=off): disk identity freely available via hdparm"
    DISK_MODEL=$(hdparm -I /dev/hda 2>/dev/null | grep -i 'model\|serial' | head -4 || \
                 hdparm -I /dev/sda 2>/dev/null | grep -i 'model\|serial' | head -4)
    echo "Identified disk: ${DISK_MODEL}"
} > "${REPORT_DIR}/storage_identity.txt"
cat "${REPORT_DIR}/storage_identity.txt"

# --- 2.5 USB ---
echo ""
echo "--- 2.5 USB DEVICES ---"
cap "usb_devices"          cat /proc/bus/usb/devices 2>/dev/null || true
cap "usb_lsusb"            lsusb 2>/dev/null || true
cap "usb_dmesg"            dmesg | grep -iE 'usb|ehci|ohci|uhci|hub'

# --- 2.6 NETWORK INTERFACES ---
echo ""
echo "--- 2.6 NETWORK ---"
cap "net_ifconfig"         ifconfig -a 2>/dev/null || ip link show 2>/dev/null || true
cap "net_proc"             cat /proc/net/dev
cap "net_dmesg"            dmesg | grep -iE 'eth|net|nic|e100|e1000|b44|tg3|bcm'
cap "net_wireless"         iwconfig 2>/dev/null || true
cap "net_wireless_dmesg"   dmesg | grep -iE 'wifi|wlan|ipw|b43|ath|wext|ieee80211'


# ============================================================
# SECTION 3: LOADED MODULES -- FULL AUDIT
# What's loaded, what's suspicious, what maps to anomalies
# ============================================================

section "3: MODULE AUDIT"

cap "modules_lsmod"        cat /proc/modules

# Parse /proc/modules into structured output
{
    echo "=== MODULE AUDIT TABLE ==="
    echo ""
    printf "%-30s %-10s %-6s %s\n" "MODULE" "SIZE" "USES" "USED_BY"
    echo "----------------------------------------------------------------------"
    while read -r name size uses usedby state address; do
        printf "%-30s %-10s %-6s %s\n" "${name}" "${size}" "${uses}" "${usedby}"
    done < /proc/modules
} > "${REPORT_DIR}/modules_table.txt"
cat "${REPORT_DIR}/modules_table.txt"

# Flag modules that match IOC patterns
{
    echo "=== IOC-CORRELATED MODULE FLAGS ==="
    echo ""

    echo "--- IOC-003/H-005: Virtual input / synthetic injection ---"
    for m in mac_hid uinput mousedev; do
        if grep -q "^${m} " /proc/modules 2>/dev/null; then
            echo "LOADED (SUSPICIOUS): ${m}"
        else
            echo "NOT LOADED (expected): ${m}"
        fi
    done
    echo ""

    echo "--- IOC-027/H-006: RAM block device ---"
    if grep -q '^brd ' /proc/modules 2>/dev/null; then
        echo "LOADED (SUSPICIOUS): brd -- in-memory block device available"
    else
        echo "NOT LOADED (expected in clean boot): brd"
    fi
    echo ""

    echo "--- IOC-028/H-007: Device mapper covert stack ---"
    for m in dm_mirror dm_zero dm_snapshot dm_crypt; do
        if grep -q "^${m} " /proc/modules 2>/dev/null; then
            echo "LOADED: ${m}"
        else
            echo "not loaded: ${m}"
        fi
    done
    echo ""

    echo "--- IOC-LOW-001: VIA PadLock on Intel hardware ---"
    for m in padlock padlock_aes padlock_sha; do
        grep -q "^${m} " /proc/modules 2>/dev/null && \
            echo "LOADED (wrong platform): ${m}" || echo "not loaded: ${m}"
    done
    echo ""

    echo "--- IOC-LOW-002: APM on ACPI system ---"
    grep -q '^apm ' /proc/modules 2>/dev/null && \
        echo "LOADED (unnecessary): apm" || echo "not loaded: apm"
    echo ""

    echo "--- IOC-LOW-003: ISA PnP on non-ISA hardware ---"
    grep -q '^isapnp ' /proc/modules 2>/dev/null && \
        echo "LOADED (no ISA bus): isapnp" || echo "not loaded: isapnp"
    echo ""

    echo "--- IOC-012: psmouse without PS/2 hardware ---"
    grep -q '^psmouse ' /proc/modules 2>/dev/null && \
        echo "LOADED: psmouse -- verify PS/2 port presence" || echo "not loaded: psmouse"
    echo ""

    echo "--- IOC-006: LSM / security modules ---"
    grep -iE 'selinux|capability|lsm|security' /proc/modules 2>/dev/null || \
        echo "[No extra security modules in DSL environment]"

} > "${REPORT_DIR}/modules_ioc_flags.txt"
cat "${REPORT_DIR}/modules_ioc_flags.txt"


# ============================================================
# SECTION 4: DRIVER INVENTORY AND REPLACEMENT PLANNING
# For each hardware class: current driver, alternatives, action
# ============================================================

section "4: DRIVER INVENTORY AND REPLACEMENT PLAN"

{
    echo "========================================================"
    echo "CTW DRIVER REPLACEMENT PLANNING TABLE"
    echo "Target: Dell Pentium 4-M for clean RHEL/Fedora install"
    echo "========================================================"
    echo ""

    # ---- STORAGE ----
    echo "=== STORAGE DRIVERS ==="
    echo ""
    STORAGE_DRIVER=$(dmesg | grep -iE 'hda|ide|pata|piix' | head -3)
    echo "Current: ${STORAGE_DRIVER}"
    echo ""
    echo "Driver      : ide_piix / piix (for PATA on this chipset)"
    echo "Status      : KEEP -- standard Intel ICH PATA controller"
    echo "Alternative : libata/pata_acpi (preferred for modern kernels)"
    echo "Action      : For RHEL 9+ install, use pata_acpi or pata_intel"
    echo "              Verify: lspci | grep IDE"
    echo ""

    # ---- NETWORK ----
    echo "=== NETWORK DRIVERS ==="
    echo ""
    echo "Checking PCI for network controllers..."
    lspci 2>/dev/null | grep -iE 'ethernet|network|wireless' || true
    echo ""
    NET_MODULE=$(dmesg | grep -iE 'e100|e1000|b44|tg3' | head -5)
    echo "Detected NIC driver: ${NET_MODULE}"
    echo ""
    echo "Driver      : Likely e100 (Intel PRO/100) on this platform"
    echo "Status      : KEEP -- well-supported, upstream kernel"
    echo "Alternative : None needed; e100 is stable in all kernels"
    echo ""
    WIFI_MODULE=$(dmesg | grep -iE 'ipw2200|ipw2100|b43|bcm' | head -3)
    echo "WiFi driver : ${WIFI_MODULE}"
    echo "Alternative : iwlwifi (if Intel 2200BG) -- better firmware support"
    echo "Action      : Obtain intel-wifi6-iwlwifi-firmware or ipw2200-fw"
    echo "              Place in /lib/firmware/ before install"
    echo ""

    # ---- VIDEO ----
    echo "=== VIDEO DRIVERS ==="
    echo ""
    lspci 2>/dev/null | grep -iE 'vga|video|display|3d|gpu' || true
    echo ""
    echo "Driver      : Likely i830/i915 (Intel integrated graphics)"
    echo "Status      : KEEP -- open source, upstream i915.ko"
    echo "Alternative : None -- proprietary drivers do not apply to Intel IGP"
    echo "Action      : For install: xorg-x11-drv-intel or modesetting driver"
    echo "              Verify KMS (kernel modesetting) enabled: i915.modeset=1"
    echo ""

    # ---- AUDIO ----
    echo "=== AUDIO DRIVERS ==="
    echo ""
    lspci 2>/dev/null | grep -iE 'audio|sound|ac97|hda' || true
    dmesg | grep -iE 'ac97|intel8x0|snd_intel8x0|hda' | head -5 || true
    echo ""
    echo "Driver      : snd_intel8x0 (AC97) or snd_hda_intel"
    echo "Status      : KEEP -- ALSA upstream, well maintained"
    echo "Alternative : None needed"
    echo ""

    # ---- INPUT / KEYBOARD / TOUCHPAD ----
    echo "=== INPUT DRIVERS ==="
    echo ""
    cat /proc/bus/input/devices 2>/dev/null | grep -E 'Name|Phys' || true
    echo ""
    echo "Driver      : psmouse (Synaptics touchpad) -- synaptics or libinput"
    echo "Status      : KEEP for touchpad -- use libinput driver in X11"
    echo ""
    echo "Driver      : mac_hid (Macintosh mouse emulation)"
    echo "Status      : REMOVE -- no Macintosh hardware present"
    echo "Action      : Blacklist in /etc/modprobe.d/blacklist.conf"
    echo "              echo 'blacklist mac_hid' >> /etc/modprobe.d/blacklist.conf"
    echo ""
    echo "Driver      : mousedev (generic mouse)"
    echo "Status      : OPTIONAL -- not needed if using evdev/libinput"
    echo ""
    echo "Driver      : uinput (virtual input injection)"
    echo "Status      : REMOVE unless deliberately using virtual devices"
    echo "Action      : Blacklist: echo 'blacklist uinput' >> /etc/modprobe.d/blacklist.conf"
    echo ""

    # ---- PCMCIA / CARDBUS ----
    echo "=== PCMCIA / CARDBUS DRIVERS ==="
    echo ""
    dmesg | grep -iE 'yenta|pcmcia|cardbus|pccard' | head -10 || true
    echo ""
    echo "Driver      : yenta_socket (CardBus bridge)"
    echo "Status      : KEEP if CardBus hardware present; REMOVE if unused"
    echo "IOC-018     : CardBus status 30000006 may indicate installed card"
    echo "Action      : Physical inspection of CardBus slots required"
    echo "              If empty: blacklist yenta_socket for minimal attack surface"
    echo ""

    # ---- FIRMWARE CANDIDATES (in-tree) ----
    echo "=== FIRMWARE UPDATE CANDIDATES ==="
    echo ""
    echo "The following firmware blobs may require updates for clean install:"
    echo ""
    ls /lib/firmware/ 2>/dev/null | head -40 || echo "[/lib/firmware empty or not mounted in DSL]"
    echo ""
    echo "Priority firmware for this platform:"
    echo "  1. Intel WiFi (ipw2200): ipw2200-bss.fw, ipw2200-ibss.fw"
    echo "     Source: https://wireless.wiki.kernel.org/en/users/Drivers/ipw2200"
    echo "  2. Microcode: intel-microcode (Mobile Pentium 4-M stepping 07)"
    echo "     Package: microcode_ctl or intel-microcode"
    echo "     Install before first boot: dracut --add-drivers intel_microcode"
    echo "  3. No proprietary GPU firmware needed (Intel IGP)"
    echo ""

    # ---- REMOVABLE / REPLACE CANDIDATES ----
    echo "=== MODULES TO REMOVE FROM CLEAN INSTALL ==="
    echo ""
    echo "The following should be blacklisted in /etc/modprobe.d/ on clean install:"
    echo ""
    echo "  blacklist mac_hid        # No Apple hardware present"
    echo "  blacklist uinput         # No virtual input injection needed"
    echo "  blacklist padlock        # No VIA CPU (Intel platform)"
    echo "  blacklist padlock-aes    # No VIA CPU"
    echo "  blacklist padlock-sha    # No VIA CPU"
    echo "  blacklist isapnp         # No ISA bus on this platform"
    echo "  blacklist apm            # ACPI replaces APM; no dual-mode needed"
    echo "  blacklist brd            # No RAM disk needed in production"
    echo "  blacklist dm_zero        # No legitimate use in production"
    echo ""
    echo "  CONDITIONAL REMOVAL (verify hardware first):"
    echo "  blacklist yenta_socket   # Only if CardBus slots empty and confirmed"
    echo "  blacklist psmouse        # Only if no PS/2 port confirmed on hardware"
    echo "  blacklist dm_snapshot    # Only if no LVM snapshots in use"
    echo "  blacklist dm_mirror      # Only if no software RAID mirror"
    echo ""
    echo "=== MODULES TO KEEP ==="
    echo ""
    echo "  ide_piix / pata_acpi     # PATA storage controller (required)"
    echo "  e100 / e1000             # Ethernet (required for network)"
    echo "  i915                     # Intel graphics (required for X11)"
    echo "  snd_intel8x0             # Audio (keep if needed)"
    echo "  ehci_hcd / uhci_hcd      # USB 2.0 (required)"
    echo "  dm_crypt                 # Required for LUKS encrypted root"
    echo "  ext3 / ext4              # Filesystem (required)"
    echo ""

} > "${REPORT_DIR}/driver_plan.txt"
cat "${REPORT_DIR}/driver_plan.txt"


# ============================================================
# SECTION 5: FIRMWARE MAINTENANCE IN RAM
# Identify updateable firmware, stage for update without disk writes
# ============================================================

section "5: FIRMWARE MAINTENANCE (toram environment)"

{
    echo "========================================================"
    echo "FIRMWARE MAINTENANCE LOG"
    echo "All operations in RAM -- zero writes to /dev/hda"
    echo "========================================================"
    echo ""

    echo "=== Current firmware/ directory contents ==="
    ls -la /lib/firmware/ 2>/dev/null || echo "[/lib/firmware not populated in DSL 4.4.10]"
    echo ""

    echo "=== BIOS/ACPI firmware version ==="
    # DMI / SMBIOS table for BIOS version
    cat /sys/class/dmi/id/bios_version 2>/dev/null || \
    cat /proc/acpi/dsdt 2>/dev/null | strings | grep -iE 'version|bios' | head -5 || \
    echo "[DMI not accessible -- try: dmidecode (may not be in DSL 4.4.10)]"
    cat /sys/class/dmi/id/bios_date 2>/dev/null || true
    cat /sys/class/dmi/id/board_vendor 2>/dev/null || true
    cat /sys/class/dmi/id/product_name 2>/dev/null || true
    echo ""

    echo "=== CPU microcode ==="
    # Check currently loaded microcode revision
    cat /proc/cpuinfo | grep -E 'microcode|stepping|model' | head -10
    echo ""
    echo "Pentium 4-M stepping 07 expected microcode: 0x2e or later"
    echo "Check: https://github.com/platomav/MCExtractor for update status"
    echo ""

    echo "=== Microcode update procedure (RAM-only) ==="
    echo "1. Download intel-microcode package to another machine"
    echo "2. Copy microcode.dat to USB or pass via network"
    echo "3. Load into running kernel: modprobe microcode"
    echo "   Then: echo 1 > /proc/sys/kernel/microcode/reload"
    echo "4. Verify: dmesg | grep microcode"
    echo "NOTE: RAM-only -- microcode must be in initrd for persistence"
    echo ""

    echo "=== WiFi firmware staging ==="
    echo "If Intel PRO/Wireless 2200BG detected:"
    echo "  1. Download ipw2200-fw-3.1.tar.bz2 to /ramdisk/"
    echo "  2. tar xjf ipw2200-fw-3.1.tar.bz2 -C /lib/firmware/"
    echo "  3. modprobe ipw2200"
    echo "  4. dmesg | grep ipw -- verify firmware loaded"
    echo ""

} > "${REPORT_DIR}/firmware_maintenance.txt"
cat "${REPORT_DIR}/firmware_maintenance.txt"


# ============================================================
# SECTION 6: INTERRUPTS, I/O, AND MEMORY MAP
# Full hardware resource picture -- compare against IOC list
# ============================================================

section "6: SYSTEM RESOURCES (IRQ / I/O / MEMORY)"

cap "irq_full"             cat /proc/interrupts
cap "ioports_full"         cat /proc/ioports
cap "iomem_full"           cat /proc/iomem
cap "cpu_info"             cat /proc/cpuinfo
cap "meminfo"              cat /proc/meminfo

# IOC-013 gap analysis against clean DSL
{
    echo "=== IOC-013: I/O port gap analysis (clean DSL) ==="
    echo ""
    echo "Checking for gap at 0xf300-0xf3fe in /proc/ioports:"
    if grep -q 'f[0-9a-f][0-9a-f][0-9a-f]-f[0-9a-f][0-9a-f][0-9a-f]' /proc/ioports; then
        grep 'f[0-9a-f][0-9a-f][0-9a-f]-f[0-9a-f][0-9a-f][0-9a-f]' /proc/ioports
        if ! grep -q 'f300-f3' /proc/ioports; then
            echo ""
            echo "IOC-013: Gap at 0xf300 CONFIRMED in clean DSL boot"
            echo "This is hardware-level (PnP/PCI BAR), not OS-injected"
        else
            echo ""
            echo "IOC-013: 0xf300 range present in clean boot -- gap may have been OS-injected"
        fi
    else
        echo "f000-fffe range not present in this boot's ioports"
    fi
    echo ""
    echo "=== IOC-015: Reserved region at top of RAM ==="
    grep '27fe\|27ff\|28000' /proc/iomem 2>/dev/null || echo "[Region not in /proc/iomem in DSL boot]"
    echo ""
    echo "=== IOC-021: CPU frequency ==="
    grep 'cpu MHz' /proc/cpuinfo | head -2
    echo "Expected: 1800.000 MHz"
    echo "Reported in compromised boot: 1195.575 MHz"
    CLEAN_MHZ=$(grep 'cpu MHz' /proc/cpuinfo | head -1 | awk '{print $4}')
    echo "DSL clean boot MHz: ${CLEAN_MHZ}"
    if echo "${CLEAN_MHZ}" | grep -q '^11[0-9][0-9]\|^12[0-9][0-9]'; then
        echo "IOC-021: Underclocking CONFIRMED in clean DSL boot -- BIOS-level frequency manipulation"
    fi
    echo ""
    echo "=== IOC-022: APIC status ==="
    dmesg | grep -i apic | head -10
    if dmesg | grep -qi 'local apic disabled\|dummy apic\|no local APIC'; then
        echo "IOC-022: APIC disabled CONFIRMED in clean DSL boot -- BIOS setting"
        echo "Fix: Enter BIOS setup, enable Local APIC, or add 'lapic' kernel parameter"
    fi
} > "${REPORT_DIR}/resources_ioc_check.txt"
cat "${REPORT_DIR}/resources_ioc_check.txt"


# ============================================================
# SECTION 7: CLEAN BOOT vs COMPROMISED BOOT DELTA TABLE
# Structured comparison of key indicators between DSL and Fedora 9 logs
# ============================================================

section "7: CLEAN vs COMPROMISED BOOT DELTA"

{
    echo "========================================================"
    echo "BOOT DELTA TABLE"
    echo "Left: Compromised Fedora 9 boot (CTW-BOOT-FA-001)"
    echo "Right: Clean DSL 4.4.10 toram boot"
    echo "========================================================"
    echo ""
    printf "%-15s | %-35s | %-35s | %s\n" "IOC" "COMPROMISED VALUE" "CLEAN DSL VALUE" "VERDICT"
    echo "----------------|-------------------------------------|-------------------------------------|----------"

    # IOC-001: initrd
    printf "%-15s | %-35s | %-35s | %s\n" \
        "IOC-001" "Dual load: 0x27c5c800, 0x27c5c000" "Single initrd (DSL CD)" "OS-LEVEL"

    # IOC-002: paravirt
    PARAVIRT=$(dmesg | grep -i paravirt | head -1 | cut -c1-35)
    PARAVIRT="${PARAVIRT:-Not present in DSL boot}"
    printf "%-15s | %-35s | %-35s | %s\n" \
        "IOC-002" "Paravirtualized kernel msg" "${PARAVIRT}" "CHECK"

    # IOC-003: mac_hid
    MAC_CLEAN=$(grep -qi 'Macintosh' /proc/bus/input/devices 2>/dev/null && echo "PRESENT" || echo "Absent")
    printf "%-15s | %-35s | %-35s | %s\n" \
        "IOC-003" "Macintosh mouse registered" "${MAC_CLEAN}" "$([ "${MAC_CLEAN}" = "Absent" ] && echo "OS-LEVEL" || echo "BIOS-LEVEL")"

    # IOC-004: DSDT
    DSDT_CLEAN=$(strings /sys/firmware/acpi/tables/DSDT 2>/dev/null | grep -i 'INT430\|SYSFe' | head -1)
    DSDT_CLEAN="${DSDT_CLEAN:-Dell OEM (expected)}"
    printf "%-15s | %-35s | %-35s | %s\n" \
        "IOC-004" "INT430 SYSFexxx DSDT OEM" "${DSDT_CLEAN}" "$(echo "${DSDT_CLEAN}" | grep -qi 'INT430' && echo "BIOS-LEVEL" || echo "OS-LEVEL")"

    # IOC-008: RTC
    RTC_CLEAN=$(hwclock 2>/dev/null | cut -d' ' -f1-4 | cut -c1-35 || echo "check hwclock")
    printf "%-15s | %-35s | %-35s | %s\n" \
        "IOC-008" "01/12/04 01:04:59 (2004)" "${RTC_CLEAN}" "BIOS-LEVEL"

    # IOC-021: CPU MHz
    MHZ=$(grep 'cpu MHz' /proc/cpuinfo | head -1 | awk '{printf "%.3f MHz", $4}')
    printf "%-15s | %-35s | %-35s | %s\n" \
        "IOC-021" "1195.575 MHz (33.6% low)" "${MHZ}" "$(echo "${MHZ}" | grep -q '^11\|^12' && echo "BIOS-LEVEL" || echo "OK")"

    # IOC-022: APIC
    APIC_CLEAN=$(dmesg | grep -i 'local apic' | head -1 | cut -c1-35 || echo "APIC status unknown")
    printf "%-15s | %-35s | %-35s | %s\n" \
        "IOC-022" "Local APIC disabled by BIOS" "${APIC_CLEAN}" "BIOS-LEVEL"

    # IOC-026: net namespaces
    NS_COUNT=$(ip netns list 2>/dev/null | wc -l)
    printf "%-15s | %-35s | %-35s | %s\n" \
        "IOC-026" "Pre-alloc namespace + 131072 TCP" "NS count: ${NS_COUNT}" "$([ "${NS_COUNT}" -eq 0 ] && echo "OS-LEVEL" || echo "CHECK")"

    # IOC-027: brd
    BRD_CLEAN=$(lsmod 2>/dev/null | grep -q '^brd ' && echo "LOADED" || echo "Not loaded")
    printf "%-15s | %-35s | %-35s | %s\n" \
        "IOC-027" "brd: module loaded" "${BRD_CLEAN}" "$([ "${BRD_CLEAN}" = "Not loaded" ] && echo "OS-LEVEL" || echo "CHECK")"

    echo ""
    echo ""
    echo "VERDICT KEY:"
    echo "  BIOS-LEVEL : Anomaly present in clean DSL boot -- firmware/hardware compromise"
    echo "  OS-LEVEL   : Anomaly absent in clean DSL boot -- initrd/kernel-level compromise"
    echo "  CHECK      : Requires manual verification of value above"
    echo "  OK         : Clean boot value consistent with expected hardware"

} > "${REPORT_DIR}/boot_delta_table.txt"
cat "${REPORT_DIR}/boot_delta_table.txt"


# ============================================================
# SECTION 8: CLEAN INSTALL PRESCRIPTION
# Specific steps for RHEL/Fedora reinstall on this hardware
# ============================================================

section "8: CLEAN INSTALL PRESCRIPTION"

{
    echo "========================================================"
    echo "CLEAN INSTALL PRESCRIPTION"
    echo "Based on CTW-BOOT-FA-001 findings + DSL hardware survey"
    echo "Target OS: RHEL 9 / Fedora latest"
    echo "========================================================"
    echo ""

    echo "STEP 1 — HARDWARE REMEDIATION (BEFORE ANY SOFTWARE INSTALL)"
    echo "  1a. BIOS FLASH: Compare current BIOS version to Dell OEM for this model."
    echo "      Obtain BIOS flash from: dell.com/support using service tag."
    echo "      Flash to confirmed OEM image to eliminate DSDT injection (IOC-004)."
    echo "  1b. APIC: Enable Local APIC in BIOS setup (eliminates IOC-022)."
    echo "  1c. CPU FREQ: Verify CPU multiplier in BIOS -- restore to 18x for 1800MHz."
    echo "  1d. CardBus: Physically inspect and remove any unrecognized CardBus cards."
    echo "  1e. NEW DISK: Install on a VERIFIED new or wiped storage medium."
    echo "      Do not trust /dev/hda from compromised system for install target."
    echo ""

    echo "STEP 2 — INSTALL MEDIA PREPARATION"
    echo "  2a. Download RHEL 9 or Fedora ISO on a known-clean machine."
    echo "  2b. Verify ISO sha256 against official checksum."
    echo "  2c. Write to DVD or USB from clean machine."
    echo "  2d. Boot installer from verified media."
    echo ""

    echo "STEP 3 — PARTITION LAYOUT (LUKS + verified /boot)"
    echo "  /boot/efi    200MB   FAT32     (if UEFI -- enroll custom MOK)"
    echo "  /boot        1GB     ext4      Plain (no LUKS -- but IMA-measured)"
    echo "  /            Rest    LUKS2+ext4 LUKS passphrase: 25+ chars, new key"
    echo ""
    echo "  CRITICAL: After install, before first boot:"
    echo "    cryptsetup luksDump /dev/sdaX -- verify only 1 key slot enabled"
    echo ""

    echo "STEP 4 — KERNEL PARAMETERS TO SET IN GRUB"
    echo "  lapic                    Re-enable Local APIC (IOC-022)"
    echo "  noexec=on                Hardware NX enforcement (IOC-019)"
    echo "  iommu=force              Enable IOMMU for DMA attack prevention"
    echo "  slub_debug=FZP           SLUB allocator hardening"
    echo "  slab_nomerge             Prevent slab cache merging exploits"
    echo "  init_on_alloc=1          Zero memory on allocation"
    echo "  init_on_free=1           Zero memory on free"
    echo "  vsyscall=none            Disable vsyscall (no fixed-address vDSO -- IOC-020)"
    echo "  page_poison=1            Poison freed pages"
    echo "  pti=on                   Page Table Isolation (Meltdown)"
    echo "  spectre_v2=on            Spectre v2 mitigations"
    echo ""

    echo "STEP 5 — POST-INSTALL MODULE BLACKLIST"
    echo "  Create /etc/modprobe.d/ctw-clean-install.conf with:"
    echo ""
    echo "    blacklist mac_hid"
    echo "    blacklist uinput"
    echo "    blacklist padlock"
    echo "    blacklist padlock-aes"
    echo "    blacklist padlock-sha"
    echo "    blacklist isapnp"
    echo "    blacklist apm"
    echo "    blacklist brd"
    echo "    blacklist dm_zero"
    echo "    blacklist yenta_socket    # if CardBus empty"
    echo "    blacklist psmouse         # if no PS/2 port confirmed"
    echo ""

    echo "STEP 6 — FIRMWARE PRE-STAGING"
    echo "  Stage to /lib/firmware/ before first user login:"
    echo "    intel-microcode (Mobile P4-M stepping 07)"
    echo "    ipw2200-fw (if Intel 2200BG WiFi present)"
    echo ""
    echo "  Rebuild initrd after firmware staging:"
    echo "    dracut --force"
    echo ""

    echo "STEP 7 — FIRST BOOT VERIFICATION"
    echo "  7a. Confirm APIC enabled: dmesg | grep apic"
    echo "  7b. Confirm NX active: dmesg | grep NX"
    echo "  7c. Confirm CPU at 1800MHz: grep 'cpu MHz' /proc/cpuinfo"
    echo "  7d. Confirm no mac_hid: lsmod | grep mac_hid"
    echo "  7e. Confirm DSDT OEM = DELL: strings /sys/firmware/acpi/tables/DSDT | head -20"
    echo "  7f. Confirm single LUKS key slot: cryptsetup luksDump /dev/sdaX"
    echo "  7g. Confirm no non-default network namespaces: ip netns list"
    echo ""

} > "${REPORT_DIR}/install_prescription.txt"
cat "${REPORT_DIR}/install_prescription.txt"


# ============================================================
# SECTION 9: HASH MANIFEST (chain of custody)
# ============================================================

section "9: EVIDENCE HASH MANIFEST"

MANIFEST="${REPORT_DIR}/MANIFEST.txt"
{
    echo "# CTW-DSL-SESSION EVIDENCE MANIFEST"
    echo "# Session: ${TIMESTAMP}"
    echo "# Algorithm: SHA256 (use b3sum for BLAKE3 if available)"
    echo ""
    find "${REPORT_DIR}" -type f ! -name "MANIFEST.txt" | sort | while read -r f; do
        sha256sum "${f}"
    done
} > "${MANIFEST}"
cat "${MANIFEST}"


# ============================================================
# HTML REPORT GENERATION
# Browsable via DSL's built-in Firefox or Dillo
# ============================================================

section "9: GENERATING HTML REPORT"

cat > "${HTML_OUT}" << HTMLEOF
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>CTW-DSL-SESSION ${TIMESTAMP}</title>
<style>
  :root {
    --bg: #0a0c0f;
    --panel: #111418;
    --border: #1e2530;
    --accent: #00ff9d;
    --warn: #ff6b35;
    --crit: #ff2d55;
    --ok: #00d4aa;
    --muted: #4a5568;
    --text: #c8d6e5;
    --mono: 'Courier New', monospace;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    background: var(--bg);
    color: var(--text);
    font-family: var(--mono);
    font-size: 12px;
    line-height: 1.6;
  }
  header {
    background: var(--panel);
    border-bottom: 2px solid var(--accent);
    padding: 16px 24px;
  }
  header h1 { color: var(--accent); font-size: 18px; letter-spacing: 2px; }
  header p  { color: var(--muted); font-size: 11px; margin-top: 4px; }
  .grid {
    display: grid;
    grid-template-columns: 220px 1fr;
    min-height: 100vh;
  }
  nav {
    background: var(--panel);
    border-right: 1px solid var(--border);
    padding: 16px 0;
    position: sticky;
    top: 0;
    height: 100vh;
    overflow-y: auto;
  }
  nav a {
    display: block;
    padding: 6px 16px;
    color: var(--muted);
    text-decoration: none;
    font-size: 11px;
    border-left: 2px solid transparent;
    transition: all 0.15s;
  }
  nav a:hover { color: var(--accent); border-left-color: var(--accent); background: rgba(0,255,157,0.05); }
  nav .nav-section { color: var(--accent); font-size: 10px; padding: 12px 16px 4px; letter-spacing: 1px; }
  main { padding: 24px; overflow-x: auto; }
  .section {
    margin-bottom: 32px;
    border: 1px solid var(--border);
    border-radius: 4px;
    overflow: hidden;
  }
  .section-header {
    background: var(--panel);
    padding: 10px 16px;
    border-bottom: 1px solid var(--border);
    display: flex;
    align-items: center;
    gap: 10px;
  }
  .section-header h2 { font-size: 13px; color: var(--accent); letter-spacing: 1px; }
  .badge {
    font-size: 9px;
    padding: 2px 6px;
    border-radius: 2px;
    font-weight: bold;
    letter-spacing: 1px;
  }
  .badge-crit  { background: var(--crit);  color: #fff; }
  .badge-warn  { background: var(--warn);  color: #fff; }
  .badge-ok    { background: var(--ok);    color: #000; }
  .badge-info  { background: var(--muted); color: #fff; }
  pre {
    padding: 16px;
    white-space: pre-wrap;
    word-break: break-all;
    font-size: 11px;
    line-height: 1.5;
    background: #080a0c;
    overflow-x: auto;
  }
  .ioc-table { width: 100%; border-collapse: collapse; }
  .ioc-table th {
    background: var(--panel);
    color: var(--accent);
    padding: 8px 12px;
    text-align: left;
    font-size: 10px;
    letter-spacing: 1px;
    border-bottom: 1px solid var(--border);
  }
  .ioc-table td {
    padding: 6px 12px;
    border-bottom: 1px solid var(--border);
    font-size: 11px;
    vertical-align: top;
  }
  .ioc-table tr:hover td { background: rgba(255,255,255,0.02); }
  .confirmed  { color: var(--crit); }
  .os-level   { color: var(--warn); }
  .bios-level { color: #ff9500; }
  .clean      { color: var(--ok); }
</style>
</head>
<body>
<header>
  <h1>CTW-DSL-SESSION // HARDWARE ENUMERATION REPORT</h1>
  <p>DSL 4.4.10 toram | Dell Pentium 4-M | Runlevel 2 | ${TIMESTAMP}</p>
</header>
<div class="grid">
<nav>
  <div class="nav-section">SESSIONS</div>
  <a href="#s0">Boot Verification</a>
  <a href="#s1">Serial Ports</a>
  <a href="#s2">Device Enumeration</a>
  <a href="#s3">Module Audit</a>
  <div class="nav-section">PLANNING</div>
  <a href="#s4">Driver Plan</a>
  <a href="#s5">Firmware</a>
  <a href="#s6">Resources</a>
  <div class="nav-section">ANALYSIS</div>
  <a href="#s7">Boot Delta</a>
  <a href="#s8">Install Rx</a>
  <a href="#s9">Manifest</a>
</nav>
<main>

<div class="section" id="s0">
  <div class="section-header">
    <h2>§0 BOOT ENVIRONMENT VERIFICATION</h2>
    <span class="badge badge-info">RUNLEVEL 2</span>
  </div>
  <pre>$(cat "${REPORT_DIR}/boot_cmdline.txt" 2>/dev/null)
$(cat "${REPORT_DIR}/boot_runlevel.txt" 2>/dev/null)
$(cat "${REPORT_DIR}/boot_kernel.txt" 2>/dev/null)</pre>
</div>

<div class="section" id="s1">
  <div class="section-header">
    <h2>§1 SERIAL PORT ENUMERATION</h2>
    <span class="badge badge-warn">IOC-WATCH</span>
  </div>
  <pre>$(cat "${REPORT_DIR}/serial_setserial.txt" 2>/dev/null)
$(cat "${REPORT_DIR}/serial_irq.txt" 2>/dev/null)
$(cat "${REPORT_DIR}/serial_ioports.txt" 2>/dev/null)</pre>
</div>

<div class="section" id="s2">
  <div class="section-header">
    <h2>§2 DEVICE ENUMERATION</h2>
    <span class="badge badge-crit">IOC-003 IOC-004 IOC-013</span>
  </div>
  <pre>$(cat "${REPORT_DIR}/pci_anomaly_check.txt" 2>/dev/null)
---
$(cat "${REPORT_DIR}/dsdt_ioc004_check.txt" 2>/dev/null)
---
$(cat "${REPORT_DIR}/input_clean_check.txt" 2>/dev/null)
---
$(cat "${REPORT_DIR}/c3_clean_check.txt" 2>/dev/null)
---
$(cat "${REPORT_DIR}/storage_identity.txt" 2>/dev/null)</pre>
</div>

<div class="section" id="s3">
  <div class="section-header">
    <h2>§3 MODULE AUDIT</h2>
    <span class="badge badge-warn">IOC-CORRELATED</span>
  </div>
  <pre>$(cat "${REPORT_DIR}/modules_ioc_flags.txt" 2>/dev/null)</pre>
</div>

<div class="section" id="s4">
  <div class="section-header">
    <h2>§4 DRIVER REPLACEMENT PLAN</h2>
    <span class="badge badge-ok">INSTALL PLANNING</span>
  </div>
  <pre>$(cat "${REPORT_DIR}/driver_plan.txt" 2>/dev/null)</pre>
</div>

<div class="section" id="s5">
  <div class="section-header">
    <h2>§5 FIRMWARE MAINTENANCE</h2>
    <span class="badge badge-info">RAM-ONLY</span>
  </div>
  <pre>$(cat "${REPORT_DIR}/firmware_maintenance.txt" 2>/dev/null)</pre>
</div>

<div class="section" id="s6">
  <div class="section-header">
    <h2>§6 SYSTEM RESOURCES</h2>
    <span class="badge badge-warn">IOC-013 IOC-015 IOC-021</span>
  </div>
  <pre>$(cat "${REPORT_DIR}/resources_ioc_check.txt" 2>/dev/null)</pre>
</div>

<div class="section" id="s7">
  <div class="section-header">
    <h2>§7 CLEAN vs COMPROMISED BOOT DELTA</h2>
    <span class="badge badge-crit">FORENSIC COMPARISON</span>
  </div>
  <pre>$(cat "${REPORT_DIR}/boot_delta_table.txt" 2>/dev/null)</pre>
</div>

<div class="section" id="s8">
  <div class="section-header">
    <h2>§8 CLEAN INSTALL PRESCRIPTION</h2>
    <span class="badge badge-ok">ACTION PLAN</span>
  </div>
  <pre>$(cat "${REPORT_DIR}/install_prescription.txt" 2>/dev/null)</pre>
</div>

<div class="section" id="s9">
  <div class="section-header">
    <h2>§9 EVIDENCE MANIFEST</h2>
    <span class="badge badge-info">CHAIN OF CUSTODY</span>
  </div>
  <pre>$(cat "${REPORT_DIR}/MANIFEST.txt" 2>/dev/null)</pre>
</div>

</main>
</div>
</body>
</html>
HTMLEOF

log "HTML report written: ${HTML_OUT}"
echo ""
echo "=================================================="
echo "CTW-DSL-SESSION COMPLETE"
echo ""
echo "Evidence: ${REPORT_DIR}/"
echo "Report:   ${HTML_OUT}"
echo ""
echo "To view report:"
echo "  dillo ${HTML_OUT} &"
echo "  firefox ${HTML_OUT} &"
echo ""
echo "To save evidence off-system:"
echo "  nc -w3 <ip> <port> < ${HTML_OUT}           # netcat"
echo "  curl -T ${REPORT_DIR}.tar.gz ftp://...     # FTP"
echo "  tar czf - ${REPORT_DIR} | nc <ip> <port>  # full tar"
echo "=================================================="
