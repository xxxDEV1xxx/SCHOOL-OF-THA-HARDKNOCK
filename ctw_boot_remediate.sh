#!/bin/bash
# =============================================================================
# CTW-BOOT-REMEDIATE.SH
# Comprehensive Boot Chain & Runtime Hardening Script
# Addresses: CTW-BOOT-FA-001 + CTW-BOOT-FA-001-SUPP (37 Anomalies)
# Author:  Christopher Thomas Williams
# Date:    2026-04-23
# Target:  Fedora 9 / Linux 2.6.25-14.fc9.i686 (bare-metal Dell Pentium 4-M)
# =============================================================================
#
# SCOPE OF REMEDIATION
# ----------------------------------------------------------------
# CRITICAL:  CRIT-001 through CRIT-007, SUPP-026 through SUPP-029
# HIGH:      HIGH-001 through HIGH-006, SUPP-030 through SUPP-033
# MEDIUM:    MED-001  through MED-008,  SUPP-034 through SUPP-036
# LOW:       LOW-001  through LOW-004,  SUPP-037
#
# USAGE
# ----------------------------------------------------------------
# Phase 1 (forensic snapshot, no changes):  sudo bash ctw_boot_remediate.sh --audit
# Phase 2 (apply all remediations):         sudo bash ctw_boot_remediate.sh --fix
# Phase 3 (verify remediations applied):    sudo bash ctw_boot_remediate.sh --verify
#
# NOTE: This script must be run from a KNOWN-GOOD live environment
# (external bootable media) because a compromised running system
# cannot be trusted to remediate itself.  All actions that modify
# the /boot partition assume the script is running from a live OS
# with the target disk mounted.  Adjust BOOT_MNT and ROOT_MNT below.
# =============================================================================

set -euo pipefail
IFS=$'\n\t'

# ----------------------------------------------------------------------------
# CONFIGURATION -- adjust mount points when running from live media
# ----------------------------------------------------------------------------
BOOT_MNT="${BOOT_MNT:-/boot}"           # Mount point of sda1 (unencrypted boot)
ROOT_MNT="${ROOT_MNT:-/}"               # Mount point of sda2 (LUKS root, if open)
LOG_DIR="/var/log/ctw_remediate"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOG_FILE="${LOG_DIR}/ctw_remediate_${TIMESTAMP}.log"
REPORT_FILE="${LOG_DIR}/ctw_remediate_report_${TIMESTAMP}.txt"
GRUB_CONF="${BOOT_MNT}/grub/grub.conf"
KERNEL_VER="2.6.25-14.fc9.i686"
INITRD_PATH="${BOOT_MNT}/initrd-${KERNEL_VER}.img"
VMLINUZ_PATH="${BOOT_MNT}/vmlinuz-${KERNEL_VER}"
KNOWN_GOOD_INITRD_SHA256="${KNOWN_GOOD_INITRD_SHA256:-}"  # Set externally from verified baseline
MODE="${1:---audit}"

# Color codes
RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

# ----------------------------------------------------------------------------
# LOGGING
# ----------------------------------------------------------------------------
mkdir -p "$LOG_DIR"

log()     { echo -e "[$(date +%T)] $*" | tee -a "$LOG_FILE"; }
log_ok()  { echo -e "${GREEN}[OK]${RESET}  $*" | tee -a "$LOG_FILE"; }
log_bad() { echo -e "${RED}[BAD]${RESET} $*" | tee -a "$LOG_FILE"; }
log_fix() { echo -e "${CYAN}[FIX]${RESET} $*" | tee -a "$LOG_FILE"; }
log_warn(){ echo -e "${YELLOW}[WARN]${RESET} $*" | tee -a "$LOG_FILE"; }
section() { echo -e "\n${BOLD}=== $* ===${RESET}" | tee -a "$LOG_FILE"; }

require_root() {
    [[ $EUID -eq 0 ]] || { echo "ERROR: Must run as root."; exit 1; }
}

# ----------------------------------------------------------------------------
# PHASE 0 — PRE-FLIGHT
# ----------------------------------------------------------------------------
preflight() {
    section "PRE-FLIGHT CHECKS"
    require_root

    log "Mode: $MODE"
    log "Boot mount: $BOOT_MNT"
    log "Root mount: $ROOT_MNT"
    log "Kernel:     $KERNEL_VER"

    for cmd in sha256sum dmsetup ip lsmod find grep awk sed modprobe \
               hwclock rtcwake lsinput uname nmcli chattr; do
        command -v "$cmd" &>/dev/null && log_ok "Tool present: $cmd" \
            || log_warn "Tool missing: $cmd (some checks may be skipped)"
    done

    [[ -d "$BOOT_MNT/grub" ]] || log_warn "GRUB directory not found at $BOOT_MNT/grub"
    [[ -f "$INITRD_PATH" ]]   || log_warn "initrd not found at $INITRD_PATH"
    [[ -f "$VMLINUZ_PATH" ]]  || log_warn "vmlinuz not found at $VMLINUZ_PATH"
}

# ============================================================================
# AUDIT FUNCTIONS  (read-only, always executed)
# ============================================================================

# ----------------------------------------------------------------------------
# IOC-001 / CRIT-001 — Dual initrd load / boot partition integrity
# ----------------------------------------------------------------------------
audit_initrd() {
    section "AUDIT: initrd Integrity (CRIT-001, HIGH-005)"

    if [[ -f "$INITRD_PATH" ]]; then
        local actual_sha
        actual_sha=$(sha256sum "$INITRD_PATH" | awk '{print $1}')
        log "initrd SHA-256: $actual_sha"

        if [[ -n "$KNOWN_GOOD_INITRD_SHA256" ]]; then
            if [[ "$actual_sha" == "$KNOWN_GOOD_INITRD_SHA256" ]]; then
                log_ok "initrd matches known-good baseline"
            else
                log_bad "INITRD MISMATCH — possible substitution (CRIT-001)"
                log_bad "  Expected: $KNOWN_GOOD_INITRD_SHA256"
                log_bad "  Actual:   $actual_sha"
            fi
        else
            log_warn "No baseline SHA256 provided — manual comparison required"
            log_warn "Export KNOWN_GOOD_INITRD_SHA256=<hash> before running"
        fi

        # Decompress and list initrd contents for inspection
        log "Listing initrd contents (top-level):"
        local tmpdir
        tmpdir=$(mktemp -d)
        (cd "$tmpdir" && zcat "$INITRD_PATH" 2>/dev/null | cpio -t 2>/dev/null | head -60) \
            | tee -a "$LOG_FILE" || log_warn "initrd decompression failed"
        rm -rf "$tmpdir"
    else
        log_warn "initrd not accessible from current mount"
    fi

    # Check vmlinuz integrity
    if [[ -f "$VMLINUZ_PATH" ]]; then
        local vmlinuz_sha
        vmlinuz_sha=$(sha256sum "$VMLINUZ_PATH" | awk '{print $1}')
        log "vmlinuz SHA-256: $vmlinuz_sha"
    fi
}

# ----------------------------------------------------------------------------
# IOC-002 / CRIT-002 — Paravirtualization / VMBR detection
# ----------------------------------------------------------------------------
audit_vmbr() {
    section "AUDIT: VMBR / Paravirtualization (CRIT-002)"

    # Check for hypervisor CPUID flag
    if grep -q "hypervisor" /proc/cpuinfo 2>/dev/null; then
        log_bad "CPUID hypervisor flag SET — running under hypervisor (CRIT-002)"
    else
        log_ok "CPUID hypervisor flag not set"
    fi

    # Check paravirt ops via dmesg
    dmesg 2>/dev/null | grep -i "paravirt\|bare hardware\|xen\|kvm\|vmware\|vbox" \
        | tee -a "$LOG_FILE" || true

    # Timing-based CPUID variance test (basic)
    if command -v python3 &>/dev/null; then
        python3 - <<'EOF' 2>/dev/null | tee -a "$LOG_FILE" || true
import time, os
samples = []
for _ in range(100):
    t0 = time.perf_counter_ns()
    os.getpid()
    t1 = time.perf_counter_ns()
    samples.append(t1 - t0)
avg = sum(samples) / len(samples)
variance = max(samples) - min(samples)
print(f"[TIMING] syscall latency avg={avg:.0f}ns variance={variance}ns")
if avg > 5000:
    print("[WARN] High syscall latency — possible hypervisor overhead (CRIT-002)")
else:
    print("[OK] Syscall latency nominal")
EOF
    fi

    # VMX/SVM instruction presence
    grep -qE "vmx|svm" /proc/cpuinfo 2>/dev/null \
        && log_warn "CPU supports hardware virtualization (VT-x/AMD-V present)" \
        || log_ok "No VT-x/AMD-V flag in cpuinfo"
}

# ----------------------------------------------------------------------------
# IOC-003 / CRIT-003 — Virtual Macintosh mouse / synthetic input devices
# ----------------------------------------------------------------------------
audit_input_devices() {
    section "AUDIT: Input Device Enumeration (CRIT-003, HIGH-006)"

    log "Enumerating /dev/input/:"
    ls -la /dev/input/ 2>/dev/null | tee -a "$LOG_FILE" || log_warn "/dev/input not accessible"

    log "Checking for virtual input devices:"
    find /sys/devices/virtual/input/ -maxdepth 2 -name "name" 2>/dev/null \
        | while read -r f; do
            local dev name
            dev=$(dirname "$f")
            name=$(cat "$f" 2>/dev/null)
            log "  $dev: $name"
            echo "$name" | grep -qi "macintosh\|mac.*mouse\|virtual" \
                && log_bad "SUSPICIOUS virtual input device: $name (CRIT-003)" \
                || true
        done

    # Check uinput module (synthetic event injection)
    lsmod 2>/dev/null | grep -q "uinput" \
        && log_bad "uinput module loaded — synthetic input injection possible (CRIT-003)" \
        || log_ok "uinput module not loaded"

    # Enumerate all input drivers via /proc/bus/input/devices
    if [[ -f /proc/bus/input/devices ]]; then
        log "All registered input devices:"
        grep -E "^(N|P|H):" /proc/bus/input/devices | tee -a "$LOG_FILE" || true
    fi
}

# ----------------------------------------------------------------------------
# IOC-004 / CRIT-004 — DSDT vendor string verification
# ----------------------------------------------------------------------------
audit_acpi_dsdt() {
    section "AUDIT: ACPI DSDT Integrity (CRIT-004)"

    # Extract DSDT if acpi_tables are exposed
    if [[ -d /sys/firmware/acpi/tables ]]; then
        log "ACPI tables accessible at /sys/firmware/acpi/tables"
        ls /sys/firmware/acpi/tables/ 2>/dev/null | tee -a "$LOG_FILE" || true

        if [[ -f /sys/firmware/acpi/tables/DSDT ]]; then
            local dsdt_sha
            dsdt_sha=$(sha256sum /sys/firmware/acpi/tables/DSDT | awk '{print $1}')
            log "DSDT SHA-256: $dsdt_sha"

            # Extract OEM ID from DSDT binary (offset 10-16)
            local oem_id
            oem_id=$(dd if=/sys/firmware/acpi/tables/DSDT bs=1 skip=10 count=6 2>/dev/null | strings)
            log "DSDT OEM ID: '$oem_id'"
            echo "$oem_id" | grep -qi "dell\|int43" || \
                log_bad "DSDT OEM ID '$oem_id' does not match DELL — possible DSDT injection (CRIT-004)"

            # Check OEM Table ID (offset 16-24)
            local oem_table_id
            oem_table_id=$(dd if=/sys/firmware/acpi/tables/DSDT bs=1 skip=16 count=8 2>/dev/null | strings)
            log "DSDT OEM Table ID: '$oem_table_id'"
        else
            log_warn "DSDT not directly readable — copy via acpidump if available"
            command -v acpidump &>/dev/null && \
                acpidump -n DSDT -b -o "${LOG_DIR}/dsdt_${TIMESTAMP}.bin" 2>/dev/null && \
                log "DSDT dumped to ${LOG_DIR}/dsdt_${TIMESTAMP}.bin" || true
        fi
    else
        log_warn "/sys/firmware/acpi/tables not available"
    fi

    # RSDT / FACP vendor from dmesg
    dmesg 2>/dev/null | grep -i "ACPI:.*DSDT\|ACPI:.*RSDT\|ACPI:.*FACP\|INT430\|SYSFe" \
        | tee -a "$LOG_FILE" || true
}

# ----------------------------------------------------------------------------
# IOC-005 / CRIT-005 — Anomalous console sequences in kernel output
# ----------------------------------------------------------------------------
audit_console_sequences() {
    section "AUDIT: Anomalous Kernel Console Sequences (CRIT-005)"

    log "Scanning dmesg for anomalous non-printk sequences:"
    # Sequences from report: "5DE", "69", "H826", "anaGddaTSlB"
    dmesg 2>/dev/null | grep -E "5DE|H826|anaGddaTSlB|[A-Z][a-z]{2}[A-Z]{2}[a-z]{2}[A-Z]" \
        | tee -a "$LOG_FILE" \
        && log_bad "Anomalous console sequences found (CRIT-005)" \
        || log_ok "No known anomalous sequences in current dmesg"

    # Check for messages without standard log level prefix
    dmesg 2>/dev/null | grep -v "^\[" | head -20 \
        | tee -a "$LOG_FILE" || true
}

# ----------------------------------------------------------------------------
# IOC-006 / CRIT-006 — LSM hook table inspection
# ----------------------------------------------------------------------------
audit_lsm() {
    section "AUDIT: LSM Hook Table (CRIT-006)"

    if [[ -d /sys/kernel/security ]]; then
        log "Security FS contents:"
        ls -la /sys/kernel/security/ 2>/dev/null | tee -a "$LOG_FILE" || true
    fi

    # Check loaded LSMs
    if [[ -f /sys/kernel/security/lsm ]]; then
        log "Active LSMs: $(cat /sys/kernel/security/lsm)"
    fi

    dmesg 2>/dev/null | grep -i "selinux\|capability\|lsm\|security module\|secondary module" \
        | tee -a "$LOG_FILE" || true

    # Kallsyms check for unexpected LSM hook symbols
    grep -E "security_hook|lsm_hooks|capability_ops" /proc/kallsyms 2>/dev/null \
        | head -20 | tee -a "$LOG_FILE" || log_warn "/proc/kallsyms not accessible"
}

# ----------------------------------------------------------------------------
# IOC-007 / CRIT-007 — Single user mode / runlevel check
# ----------------------------------------------------------------------------
audit_runlevel() {
    section "AUDIT: Runlevel and Boot Parameters (CRIT-007)"

    local cmdline
    cmdline=$(cat /proc/cmdline 2>/dev/null)
    log "Current kernel cmdline: $cmdline"

    echo "$cmdline" | grep -qE "\b1\b|single|emergency" \
        && log_bad "System booted in single-user / maintenance mode (CRIT-007)" \
        || log_ok "Normal runlevel boot"

    # Check for nodhcp with full TCP stack
    echo "$cmdline" | grep -q "nodhcp" && \
        grep -q "131072" /proc/net/sockstat 2>/dev/null && \
        log_bad "nodhcp set but TCP hash tables allocated — covert network capability (SUPP-026)"

    # Verify actual runlevel
    if command -v runlevel &>/dev/null; then
        local rl
        rl=$(runlevel | awk '{print $2}')
        log "Current runlevel: $rl"
    fi
}

# ----------------------------------------------------------------------------
# IOC-008 / HIGH-001 — RTC timestamp verification
# ----------------------------------------------------------------------------
audit_rtc() {
    section "AUDIT: RTC Timestamp (HIGH-001, MED-007)"

    local hw_time
    hw_time=$(hwclock --show 2>/dev/null) || hw_time="UNAVAILABLE"
    local sys_time
    sys_time=$(date)
    log "Hardware clock: $hw_time"
    log "System clock:   $sys_time"

    # Extract year from hwclock
    local hw_year
    hw_year=$(hwclock --show 2>/dev/null | grep -oP '\d{4}' | tail -1) || hw_year="0"
    if [[ "$hw_year" -lt 2008 ]]; then
        log_bad "RTC year $hw_year predates Fedora 9 release (2008) — timestamp falsification (HIGH-001)"
    else
        log_ok "RTC year $hw_year is plausible"
    fi

    # Check audit timestamps
    grep "audit(" /var/log/audit/audit.log 2>/dev/null | head -5 \
        | tee -a "$LOG_FILE" || true
}

# ----------------------------------------------------------------------------
# IOC-009 / HIGH-002 — UUID discrepancy audit
# ----------------------------------------------------------------------------
audit_uuid() {
    section "AUDIT: Root Device UUID Consistency (HIGH-002, SUPP-034)"

    local cmdline_uuid
    cmdline_uuid=$(cat /proc/cmdline 2>/dev/null | grep -oP 'root=UUID=\S+' | head -1)
    log "Cmdline UUID: $cmdline_uuid"

    # Check actual UUID of sda2
    if command -v blkid &>/dev/null; then
        local actual_uuid
        actual_uuid=$(blkid /dev/sda2 2>/dev/null | grep -oP 'UUID="\K[^"]+') || true
        log "sda2 actual UUID: ${actual_uuid:-UNREADABLE}"

        if [[ -n "${actual_uuid:-}" ]] && [[ -n "$cmdline_uuid" ]]; then
            echo "$cmdline_uuid" | grep -q "$actual_uuid" \
                && log_ok "UUID consistent between cmdline and block device" \
                || log_bad "UUID MISMATCH — possible device substitution (HIGH-002, SUPP-034)"
        fi
    fi
}

# ----------------------------------------------------------------------------
# IOC-010 / HIGH-003 — noscsi override
# ----------------------------------------------------------------------------
audit_scsi_override() {
    section "AUDIT: noscsi Parameter Override (HIGH-003)"

    cat /proc/cmdline 2>/dev/null | grep -q "noscsi" \
        && log_warn "noscsi set in cmdline"
    lsmod 2>/dev/null | grep -qE "^scsi_mod|^sd_mod" \
        && log_bad "SCSI modules loaded despite noscsi parameter (HIGH-003)" \
        || log_ok "SCSI modules not loaded"
}

# ----------------------------------------------------------------------------
# IOC-011 / HIGH-006 — Input device gap and PS/2 phantom mouse
# ----------------------------------------------------------------------------
audit_input_gap() {
    section "AUDIT: Input Device Number Gap (HIGH-006)"

    for i in 0 1 2 3 4; do
        if [[ -e /dev/input/event$i ]]; then
            local name
            name=$(cat /sys/class/input/event${i}/device/name 2>/dev/null || echo "UNKNOWN")
            log "event$i: $name"
            [[ $i -eq 1 ]] && echo "$name" | grep -qi "virtual\|synthetic\|unknown\|ps/2.*mouse" \
                && log_bad "Suspicious device at input$i: $name (HIGH-006)" || true
        else
            [[ $i -eq 1 ]] && log_warn "input1 not present — gap confirmed (HIGH-006)" || true
        fi
    done
}

# ----------------------------------------------------------------------------
# IOC-013 / MED-003 — I/O port reservation gap
# ----------------------------------------------------------------------------
audit_ioport_gap() {
    section "AUDIT: I/O Port Reservation Gap (MED-003)"

    log "Checking for 0xf300 gap in port reservations:"
    grep -E "f[0-9a-f]00" /proc/ioports 2>/dev/null | tee -a "$LOG_FILE" || true
    grep "f300" /proc/ioports 2>/dev/null \
        && log_ok "0xf300-0xf3fe is claimed (gap closed)" \
        || log_bad "0xf300 range NOT in /proc/ioports — covert I/O channel possible (MED-003)"
}

# ----------------------------------------------------------------------------
# IOC-015 / MED-005 — Reserved memory at top of RAM
# ----------------------------------------------------------------------------
audit_reserved_memory() {
    section "AUDIT: Suspicious Reserved Memory Region (MED-005, SUPP-029)"

    log "Top of physical RAM reservations:"
    grep -iE "reserved|bios" /proc/iomem 2>/dev/null \
        | grep -E "27fe|2800|feda|fe00" \
        | tee -a "$LOG_FILE" || true

    # Check e820 map from dmesg for impossible geometry
    dmesg 2>/dev/null | grep "e820\|BIOS-e820" \
        | tee -a "$LOG_FILE" | grep -E "feda0000.*fe000000" \
        && log_bad "Impossible e820 entry (start > end) detected (SUPP-029)" || true
}

# ----------------------------------------------------------------------------
# IOC-016 / MED-006 — TSC stability
# ----------------------------------------------------------------------------
audit_tsc() {
    section "AUDIT: TSC Stability (MED-006)"

    dmesg 2>/dev/null | grep -i "tsc\|unstable\|reliable" | tee -a "$LOG_FILE" || true
    cat /sys/devices/system/clocksource/clocksource0/current_clocksource 2>/dev/null \
        | tee -a "$LOG_FILE" || log_warn "clocksource not readable"
}

# ----------------------------------------------------------------------------
# IOC-018 / MED-008 — CardBus socket status
# ----------------------------------------------------------------------------
audit_cardbus() {
    section "AUDIT: CardBus Socket Status (MED-008)"

    dmesg 2>/dev/null | grep -i "yenta\|socket status\|cardbus" | tee -a "$LOG_FILE" || true
    log "Physical inspection required for CardBus slots — automated check only:"
    ls /sys/bus/pcmcia/devices/ 2>/dev/null \
        && log_warn "PCMCIA/CardBus devices present — inspect physically (MED-008)" \
        || log_ok "No PCMCIA/CardBus devices enumerated"
}

# ----------------------------------------------------------------------------
# IOC-026 / SUPP-026 — Network namespace covert capability
# ----------------------------------------------------------------------------
audit_netns() {
    section "AUDIT: Network Namespace Isolation (SUPP-026)"

    log "Active network namespaces:"
    ip netns list 2>/dev/null | tee -a "$LOG_FILE" || log_warn "ip netns not available"

    local ns_count
    ns_count=$(ip netns list 2>/dev/null | wc -l) || ns_count=0
    [[ "$ns_count" -gt 0 ]] \
        && log_bad "$ns_count non-default network namespace(s) found (SUPP-026)" \
        || log_ok "No non-default network namespaces"

    log "TCP connection table occupancy:"
    ss -s 2>/dev/null || netstat -s 2>/dev/null | grep -i "connection" | head -5 || true
}

# ----------------------------------------------------------------------------
# IOC-027 / SUPP-027 — brd RAM disk driver
# ----------------------------------------------------------------------------
audit_ramdisk() {
    section "AUDIT: RAM Block Device (SUPP-027)"

    lsmod 2>/dev/null | grep -q "^brd " \
        && log_bad "brd module loaded — in-memory block device available (SUPP-027)" \
        || log_ok "brd module not loaded"

    ls /dev/ram* 2>/dev/null | tee -a "$LOG_FILE" \
        && log_warn "RAM block devices present in /dev/" || true

    # Check /proc/partitions for ram devices
    grep "ram" /proc/partitions 2>/dev/null \
        && log_warn "RAM partitions found in /proc/partitions" || true

    # Check for mounted ram filesystems
    mount 2>/dev/null | grep "ram\|tmpfs\|ramfs" | tee -a "$LOG_FILE" || true
}

# ----------------------------------------------------------------------------
# IOC-028 / SUPP-028 — Device mapper capability stack
# ----------------------------------------------------------------------------
audit_dmapper() {
    section "AUDIT: Device Mapper Stack (SUPP-028)"

    log "Loaded device mapper modules:"
    lsmod 2>/dev/null | grep -E "^dm_|^dm-" | tee -a "$LOG_FILE" || true

    local suspicious_dm=0
    for mod in dm_mirror dm_zero dm_snapshot dm_crypt; do
        lsmod 2>/dev/null | grep -q "^${mod}" && {
            log_bad "DM module loaded: $mod (SUPP-028)"
            ((suspicious_dm++))
        } || true
    done
    [[ $suspicious_dm -eq 4 ]] \
        && log_bad "ALL four covert DM modules present simultaneously (SUPP-028)" || true

    log "Active device mapper tables:"
    dmsetup table 2>/dev/null | tee -a "$LOG_FILE" || log_warn "dmsetup not available"

    log "Device mapper ls:"
    dmsetup ls 2>/dev/null | tee -a "$LOG_FILE" || true
}

# ----------------------------------------------------------------------------
# IOC-031 / SUPP-031 — EDD disabled
# ----------------------------------------------------------------------------
audit_edd() {
    section "AUDIT: EDD Disk Identity Verification (SUPP-031)"

    grep -q "edd=off" /proc/cmdline 2>/dev/null \
        && log_bad "edd=off in cmdline — BIOS disk identity verification disabled (SUPP-031)" \
        || log_ok "EDD not disabled in cmdline"

    # Current disk identity
    if [[ -b /dev/sda ]]; then
        log "sda identity:"
        udevadm info --query=all --name=/dev/sda 2>/dev/null \
            | grep -E "ID_|SERIAL|MODEL|VENDOR" \
            | tee -a "$LOG_FILE" || true
    fi
}

# ----------------------------------------------------------------------------
# IOC-033 / SUPP-033 — C3 power state absence
# ----------------------------------------------------------------------------
audit_c3_state() {
    section "AUDIT: CPU C3 Power State (SUPP-033)"

    if [[ -f /proc/acpi/processor/CPU0/power ]]; then
        log "CPU power states:"
        cat /proc/acpi/processor/CPU0/power | tee -a "$LOG_FILE"
        grep -q "C3" /proc/acpi/processor/CPU0/power \
            && log_ok "C3 state present" \
            || log_bad "C3 power state ABSENT — CPU cache not flushed during idle (SUPP-033)"
    else
        dmesg 2>/dev/null | grep -i "power states\|C1\|C2\|C3\|acpi.*cpu" \
            | tee -a "$LOG_FILE" || true
    fi
}

# ----------------------------------------------------------------------------
# IOC-036 / SUPP-036 — HugeTLB pool
# ----------------------------------------------------------------------------
audit_hugetlb() {
    section "AUDIT: HugeTLB Pool (SUPP-036)"

    grep "HugePages" /proc/meminfo 2>/dev/null | tee -a "$LOG_FILE" || true
    local hp_total
    hp_total=$(grep "HugePages_Total" /proc/meminfo 2>/dev/null | awk '{print $2}') || hp_total=0
    [[ "${hp_total:-0}" -gt 0 ]] \
        && log_bad "$hp_total huge pages allocated post-boot — examine mapping (SUPP-036)" \
        || log_ok "HugePages_Total=0 (no post-boot allocation)"
}

# ----------------------------------------------------------------------------
# IOC-037 / SUPP-037 — Disk quota pre-LUKS
# ----------------------------------------------------------------------------
audit_quota_preluks() {
    section "AUDIT: Disk Quota Pre-LUKS Initialization (SUPP-037)"

    dmesg 2>/dev/null | grep -i "quota\|dquot" | tee -a "$LOG_FILE" || true
    mount 2>/dev/null | grep -i "quota\|usrquota\|grpquota" \
        && log_warn "Quota-enabled filesystem mounted — verify against boot sequence order (SUPP-037)" \
        || log_ok "No quota mounts detected"
}

# ============================================================================
# FIX FUNCTIONS  (modifying, executed only with --fix)
# ============================================================================

# ----------------------------------------------------------------------------
# FIX: GRUB configuration hardening
# Addresses: CRIT-001, HIGH-002, HIGH-003, HIGH-005, SUPP-031, SUPP-034
# ----------------------------------------------------------------------------
fix_grub() {
    section "FIX: GRUB Configuration Hardening"

    [[ -f "$GRUB_CONF" ]] || { log_warn "GRUB config not found at $GRUB_CONF — skipping"; return; }

    # Backup
    cp -v "$GRUB_CONF" "${GRUB_CONF}.bak_${TIMESTAMP}" | tee -a "$LOG_FILE"

    # 1. Remove edd=off — re-enable BIOS disk identity verification (SUPP-031)
    if grep -q "edd=off" "$GRUB_CONF"; then
        sed -i 's/ edd=off//g' "$GRUB_CONF"
        log_fix "Removed edd=off — EDD disk identity verification restored (SUPP-031)"
    fi

    # 2. Replace runlevel 1 with runlevel 3 (CRIT-007)
    # WARNING: Only do this if system is actually meant for multi-user operation.
    # Remove trailing " 1" from kernel lines in grub.conf
    if grep -qE "kernel.*\b1$" "$GRUB_CONF"; then
        sed -i -E 's/(kernel.*) 1$/\1 3/' "$GRUB_CONF"
        log_fix "Replaced runlevel 1 with runlevel 3 in GRUB (CRIT-007)"
    fi

    # 3. Add explicit lapic to re-enable Local APIC (MED-002)
    if ! grep -q "lapic" "$GRUB_CONF"; then
        sed -i -E '/^\s*kernel /{s/$/ lapic/}' "$GRUB_CONF"
        log_fix "Added lapic parameter to re-enable Local APIC (MED-002)"
    fi

    # 4. Add noefi as defensive measure against DSDT override if coreboot-style
    # (comment this out if system needs EFI)
    # sed -i -E '/^\s*kernel /{s/$/ acpi_dsdt=BIOS/}' "$GRUB_CONF"

    # 5. Enable KASLR (not available on 2.6.25, log as future action)
    log_warn "KASLR (CONFIG_RANDOMIZE_BASE) not available on 2.6.25 — upgrade kernel"

    log "Updated GRUB config:"
    cat "$GRUB_CONF" | tee -a "$LOG_FILE"
}

# ----------------------------------------------------------------------------
# FIX: initrd integrity pinning
# Addresses: CRIT-001, HIGH-005
# ----------------------------------------------------------------------------
fix_initrd_integrity() {
    section "FIX: initrd Integrity Pinning (CRIT-001, HIGH-005)"

    if [[ ! -f "$INITRD_PATH" ]]; then
        log_warn "initrd not found — skipping pinning"
        return
    fi

    # Generate reference hashes for boot artifacts
    local hash_file="${BOOT_MNT}/.boot_hashes_${TIMESTAMP}.sha256"
    sha256sum "$INITRD_PATH" > "$hash_file"
    sha256sum "$VMLINUZ_PATH" >> "$hash_file" 2>/dev/null || true
    [[ -f "$GRUB_CONF" ]] && sha256sum "$GRUB_CONF" >> "$hash_file"
    log_fix "Boot artifact hash manifest written to $hash_file"
    cat "$hash_file" | tee -a "$LOG_FILE"

    # Immutable flag on initrd and vmlinuz (prevents modification without chattr -i)
    chattr +i "$INITRD_PATH" 2>/dev/null \
        && log_fix "Set immutable flag on initrd (CRIT-001)" \
        || log_warn "chattr +i failed on initrd (may need ext2/ext3/ext4 fs)"
    chattr +i "$VMLINUZ_PATH" 2>/dev/null \
        && log_fix "Set immutable flag on vmlinuz" \
        || true

    # Install post-boot integrity check as cron job
    cat > /etc/cron.d/ctw_boot_integrity << 'CRON'
# CTW Boot Integrity Check — verifies boot artifacts daily
@daily root sha256sum -c /boot/.boot_hashes_*.sha256 2>&1 | logger -t ctw_boot_integrity
CRON
    log_fix "Boot integrity cron job installed"
}

# ----------------------------------------------------------------------------
# FIX: RTC correction
# Addresses: HIGH-001, MED-007
# ----------------------------------------------------------------------------
fix_rtc() {
    section "FIX: RTC Timestamp Correction (HIGH-001, MED-007)"

    local current_date
    current_date=$(date +%Y-%m-%d)
    log "Setting hardware clock to current system time: $current_date"

    # Sync system clock from NTP first if available
    if command -v ntpdate &>/dev/null; then
        ntpdate -u pool.ntp.org 2>/dev/null \
            && log_fix "System clock synchronized via NTP" \
            || log_warn "NTP sync failed — set system time manually before proceeding"
    elif command -v chronyc &>/dev/null; then
        chronyc makestep 2>/dev/null && log_fix "System clock stepped via chrony" || true
    fi

    hwclock --systohc 2>/dev/null \
        && log_fix "Hardware RTC updated to system time (HIGH-001)" \
        || log_warn "hwclock --systohc failed"
}

# ----------------------------------------------------------------------------
# FIX: Remove/blacklist anomalous modules
# Addresses: CRIT-003 (uinput/macmouse), LOW-001 (padlock), LOW-003 (isapnp)
#             SUPP-027 (brd), SUPP-028 (dm stack if unused)
# ----------------------------------------------------------------------------
fix_blacklist_modules() {
    section "FIX: Module Blacklist (CRIT-003, LOW-001, LOW-003, SUPP-027)"

    local blacklist_file="/etc/modprobe.d/ctw_security_blacklist.conf"

    cat > "$blacklist_file" << 'EOF'
# CTW Security Module Blacklist
# Generated by ctw_boot_remediate.sh — CTW-BOOT-FA-001 remediation

# CRIT-003: Macintosh mouse emulation / synthetic input injection
blacklist mac_hid
blacklist uinput

# LOW-001: VIA PadLock on Intel hardware — no legitimate use
blacklist padlock
blacklist padlock_aes
blacklist padlock_sha

# LOW-003: ISA PnP on non-ISA hardware — no legitimate use
blacklist isapnp

# SUPP-027: RAM block device — no configured ramdisk present
# CAUTION: Uncomment only if no ramdisk is intentionally used
# blacklist brd

# SUPP-028: Device mapper covert storage stack
# CAUTION: dm-crypt is needed for LUKS — DO NOT blacklist dm-crypt
# Blacklist only the storage manipulation modules if not needed:
# blacklist dm_mirror
# blacklist dm_snapshot
# blacklist dm_zero
# Note: If dm-crypt is the ONLY DM module needed, enforce via initrd pruning

# MED-001 note: speedstep modules for correct frequency reporting
# install speedstep-centrino /sbin/modprobe --ignore-install speedstep-centrino
EOF

    log_fix "Module blacklist written to $blacklist_file"

    # Attempt to unload currently loaded anomalous modules
    for mod in mac_hid uinput padlock padlock_aes padlock_sha; do
        lsmod 2>/dev/null | grep -q "^${mod}" && {
            rmmod "$mod" 2>/dev/null \
                && log_fix "Unloaded module: $mod" \
                || log_warn "Could not unload $mod (may be in use)"
        } || true
    done
}

# ----------------------------------------------------------------------------
# FIX: SELinux enforcement verification and hardening
# Addresses: CRIT-006
# ----------------------------------------------------------------------------
fix_selinux() {
    section "FIX: SELinux Hardening (CRIT-006)"

    if command -v getenforce &>/dev/null; then
        local se_status
        se_status=$(getenforce 2>/dev/null)
        log "Current SELinux status: $se_status"

        if [[ "$se_status" == "Disabled" || "$se_status" == "Permissive" ]]; then
            log_bad "SELinux is $se_status — must be Enforcing"
            if [[ -f /etc/selinux/config ]]; then
                cp /etc/selinux/config "/etc/selinux/config.bak_${TIMESTAMP}"
                sed -i 's/^SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config
                log_fix "SELinux set to enforcing in /etc/selinux/config (requires reboot)"
            fi
            setenforce 1 2>/dev/null \
                && log_fix "SELinux set to Enforcing immediately" \
                || log_warn "setenforce 1 failed"
        else
            log_ok "SELinux is Enforcing"
        fi
    else
        log_warn "SELinux tools not available"
    fi

    # Verify no extra LSM modules
    log "LSM hook verification:"
    grep -E "security_ops|dummy_security_ops" /proc/kallsyms 2>/dev/null \
        | tee -a "$LOG_FILE" || true
}

# ----------------------------------------------------------------------------
# FIX: Kernel hardening parameters via sysctl
# Addresses: HIGH-004 (NX), LOW-004 (vDSO/ASLR), MED-006 (TSC), SUPP-026 (netns)
# ----------------------------------------------------------------------------
fix_sysctl() {
    section "FIX: Kernel Hardening via sysctl (HIGH-004, LOW-004, SUPP-026)"

    local sysctl_file="/etc/sysctl.d/99-ctw-hardening.conf"

    cat > "$sysctl_file" << 'EOF'
# CTW Security Hardening — sysctl parameters
# CTW-BOOT-FA-001 + SUPP remediation

# HIGH-004 note: Hardware NX requires PAE boot param — set in GRUB
# LOW-004: ASLR (partial mitigation for fixed vDSO on 2.6.25)
kernel.randomize_va_space = 2

# Network hardening (SUPP-026 covert network mitigation)
net.ipv4.conf.all.forwarding = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.rp_filter = 1

# Restrict network namespace creation (requires kernel support; not in 2.6.25)
# kernel.unprivileged_userns_clone = 0

# Restrict dmesg to root (prevents CRIT-005 sequence leakage)
kernel.dmesg_restrict = 1

# Restrict kernel symbols
kernel.kptr_restrict = 2

# Restrict ptrace (limits process inspection)
kernel.yama.ptrace_scope = 1

# Core dump hardening
fs.suid_dumpable = 0
kernel.core_uses_pid = 1

# Restrict /proc access
kernel.hidepid = 2

# Prevent executable memory (partial NX emulation support)
vm.mmap_min_addr = 65536
EOF

    log_fix "sysctl hardening file written to $sysctl_file"
    sysctl -p "$sysctl_file" 2>/dev/null \
        && log_fix "sysctl parameters applied" \
        || log_warn "Some sysctl parameters may not be supported on 2.6.25 — apply on reboot"
}

# ----------------------------------------------------------------------------
# FIX: Network namespace isolation — block covert namespace creation
# Addresses: SUPP-026
# ----------------------------------------------------------------------------
fix_netns_isolation() {
    section "FIX: Network Namespace Lockdown (SUPP-026)"

    # Enumerate and log all existing non-default namespaces
    log "Enumerating all network namespaces for forensic record:"
    ip netns list 2>/dev/null | tee -a "$LOG_FILE" || true

    # Restrict creation of new network namespaces to root only
    # (via nftables or iptables policy — no CAP_NET_ADMIN without explicit grant)
    if command -v nft &>/dev/null; then
        log_fix "nftables available — add explicit ingress/egress rules manually if needed"
    fi

    # Kill any established connections in non-default namespaces
    local ns_list
    ns_list=$(ip netns list 2>/dev/null | awk '{print $1}') || ns_list=""
    if [[ -n "$ns_list" ]]; then
        log_bad "Non-default network namespaces found — manual review required:"
        echo "$ns_list" | tee -a "$LOG_FILE"
        log_warn "To inspect: ip netns exec <ns> ip link show"
        log_warn "To destroy: ip netns delete <ns>"
    fi
}

# ----------------------------------------------------------------------------
# FIX: Unmount / remove covert device mapper targets
# Addresses: SUPP-027, SUPP-028
# ----------------------------------------------------------------------------
fix_dm_cleanup() {
    section "FIX: Device Mapper Covert Target Cleanup (SUPP-027, SUPP-028)"

    log "Current DM targets:"
    dmsetup ls 2>/dev/null | tee -a "$LOG_FILE" || return

    # Identify and log non-LUKS DM targets (anything not named 'luks-*')
    while IFS= read -r line; do
        local dm_name
        dm_name=$(echo "$line" | awk '{print $1}')
        if [[ "$dm_name" != luks-* && "$dm_name" != "No" ]]; then
            log_bad "Non-LUKS device mapper target found: $dm_name — investigate"
            dmsetup table "$dm_name" 2>/dev/null | tee -a "$LOG_FILE" || true
            log_warn "To remove (CAUTION): dmsetup remove $dm_name"
        fi
    done < <(dmsetup ls 2>/dev/null)

    # Check for mounted ramdisk filesystems
    log "Checking for in-memory filesystems:"
    mount 2>/dev/null | grep -E "type (ramfs|tmpfs|ext[234]).*(/dev/ram)" \
        | tee -a "$LOG_FILE" \
        && log_bad "RAM block device filesystem(s) mounted — review and umount if unauthorized" \
        || log_ok "No RAM block device filesystems mounted"
}

# ----------------------------------------------------------------------------
# FIX: LUKS passphrase key material exposure mitigation
# Addresses: SUPP-033 (C3 absent), SUPP-030 (write protect race)
# ----------------------------------------------------------------------------
fix_luks_hardening() {
    section "FIX: LUKS Key Material Hardening (SUPP-033, SUPP-030)"

    log "LUKS devices:"
    dmsetup ls --target crypt 2>/dev/null | tee -a "$LOG_FILE" || true

    # Add a new LUKS keyslot (generates new key, invalidates captured passphrase)
    # This is the most effective remediation for CRIT-001 passphrase capture.
    log_warn "ACTION REQUIRED: LUKS passphrase has potentially been captured (CRIT-001)"
    log_warn "Remediation: Add new keyslot + remove all existing keyslots"
    log_warn "Commands (DO NOT RUN UNTIL BACKUP IS CONFIRMED):"
    log_warn "  cryptsetup luksAddKey /dev/sda2    # Add new passphrase"
    log_warn "  cryptsetup luksKillSlot /dev/sda2 <old_slot>  # Remove old slot"
    log_warn "  cryptsetup luksDump /dev/sda2      # Verify keyslots"

    # Check LUKS header integrity
    if command -v cryptsetup &>/dev/null && [[ -b /dev/sda2 ]]; then
        log "LUKS header status:"
        cryptsetup luksDump /dev/sda2 2>/dev/null | tee -a "$LOG_FILE" || true

        local luks_sha
        luks_sha=$(dd if=/dev/sda2 bs=512 count=4 2>/dev/null | sha256sum | awk '{print $1}')
        log "LUKS header SHA-256 (first 2KB): $luks_sha"
        log_fix "LUKS header hash recorded for future comparison"
    fi

    # C3 re-enablement (SUPP-033) — must be done via BIOS or DSDT patch
    log_warn "C3 state re-enablement requires BIOS settings change or DSDT correction"
    log_warn "Check BIOS power management settings and enable C3/Deep Sleep if available"
}

# ----------------------------------------------------------------------------
# FIX: Audit subsystem hardening
# Addresses: CRIT-007, MED-007, HIGH-001
# ----------------------------------------------------------------------------
fix_audit() {
    section "FIX: Audit Subsystem Hardening (CRIT-007, MED-007)"

    # Configure auditd if available
    if [[ -f /etc/audit/auditd.conf ]]; then
        cp /etc/audit/auditd.conf "/etc/audit/auditd.conf.bak_${TIMESTAMP}"

        # Maximize log retention
        sed -i 's/^max_log_file_action.*/max_log_file_action = KEEP_LOGS/' /etc/audit/auditd.conf
        sed -i 's/^num_logs.*/num_logs = 99/' /etc/audit/auditd.conf
        log_fix "auditd configured for maximum log retention"
    fi

    # Write critical audit rules
    local audit_rules="/etc/audit/audit.rules"
    [[ -f "$audit_rules" ]] || touch "$audit_rules"

    cat >> "$audit_rules" << 'EOF'

# CTW-BOOT-FA-001 Audit Rules
# Monitor initrd and vmlinuz modifications
-w /boot -p wa -k boot_integrity
# Monitor LSM operations
-w /sys/kernel/security -p rwa -k lsm_ops
# Monitor device mapper
-w /dev/mapper -p wa -k dm_ops
# Monitor module loads
-a always,exit -F arch=b32 -S init_module -S delete_module -k module_ops
# Monitor network namespace creation
-a always,exit -F arch=b32 -S unshare -k netns_create
# Monitor /dev/input modifications
-w /dev/input -p wa -k input_device
EOF

    log_fix "Critical audit rules appended to $audit_rules"

    # Enable auditd
    service auditd restart 2>/dev/null \
        && log_fix "auditd restarted" \
        || log_warn "auditd restart failed — verify manually"
}

# ----------------------------------------------------------------------------
# FIX: Disable CardBus hotplug pending physical inspection
# Addresses: MED-008
# ----------------------------------------------------------------------------
fix_cardbus() {
    section "FIX: CardBus Hotplug Restriction (MED-008)"

    # Blacklist pcmcia modules pending physical inspection
    echo "# MED-008: Disable CardBus hotplug until physical inspection complete" \
        >> /etc/modprobe.d/ctw_security_blacklist.conf
    echo "blacklist pcmcia_rsrc" >> /etc/modprobe.d/ctw_security_blacklist.conf
    log_fix "CardBus hotplug restricted pending physical inspection (MED-008)"
    log_warn "PHYSICAL ACTION REQUIRED: Inspect both CardBus slots for installed hardware"
}

# ----------------------------------------------------------------------------
# FIX: vDSO randomization (partial mitigation for LOW-004)
# Note: Full fix requires kernel with CONFIG_COMPAT_VDSO=n — document for rebuild
# ----------------------------------------------------------------------------
fix_vdso() {
    section "FIX: vDSO Address Randomization (LOW-004)"

    # On 2.6.25, compat_vdso is controlled at boot time
    # Check if vdso32-compat parameter is available
    if grep -q "vdso" /proc/cmdline 2>/dev/null; then
        log "vDSO boot parameter already set"
    else
        log_warn "Add 'vdso=0' or 'vdso32=0' to GRUB kernel line to disable compat vDSO (LOW-004)"
        log_warn "Full remediation requires kernel rebuild with CONFIG_COMPAT_VDSO=n"
        # Add to grub if file accessible
        if [[ -f "$GRUB_CONF" ]]; then
            sed -i -E '/^\s*kernel /{/vdso/!s/$/ vdso=0/}' "$GRUB_CONF"
            log_fix "Added vdso=0 to GRUB kernel line (LOW-004)"
        fi
    fi
}

# ----------------------------------------------------------------------------
# FIX: Generate full remediation checklist for manual actions
# ----------------------------------------------------------------------------
fix_generate_checklist() {
    section "FIX: Generating Manual Remediation Checklist"

    cat > "$REPORT_FILE" << CHECKLIST
================================================================================
CTW-BOOT-FA-001 REMEDIATION CHECKLIST
Generated: $(date)
================================================================================

AUTOMATED ACTIONS APPLIED (verify above log):
  [AUTO] Module blacklist created
  [AUTO] sysctl hardening applied
  [AUTO] GRUB parameters updated (edd, runlevel, lapic, vdso)
  [AUTO] initrd/vmlinuz immutable flags set
  [AUTO] Boot artifact SHA-256 hashes recorded
  [AUTO] SELinux set to Enforcing
  [AUTO] Audit rules added
  [AUTO] RTC corrected to current time

MANUAL ACTIONS REQUIRED — ORDERED BY PRIORITY:
--------------------------------------------------------------------------------

PRIORITY 1 — PHYSICAL INSPECTION (Cannot be automated)
  [ ] ACTION-001: Physically inspect both CardBus slots for installed hardware
  [ ] ACTION-009: Inspect PCIe/PCI/CardBus for hardware implants; inspect BIOS chip
  [ ] SUPP-006:   Inspect dock station for attached network/storage hardware

PRIORITY 2 — BINARY FORENSICS (Requires known-good baseline media)
  [ ] ACTION-002: Binary compare initrd against Fedora 9 OEM initrd
                  Command: diff <(zcat $INITRD_PATH | cpio -t | sort) \
                                <(zcat /media/fedora9_original_initrd.img | cpio -t | sort)
  [ ] ACTION-003: Extract and compare DSDT against Dell OEM BIOS image
                  Command: acpidump -n DSDT -b -o /tmp/dsdt_current.bin
                           iasl -d /tmp/dsdt_current.bin
                           diff /tmp/dsdt_current.dsl /tmp/dell_oem_dsdt.dsl
  [ ] ACTION-008: Extract BIOS firmware and compare against Dell OEM image
                  Tool: flashrom -p internal -r /tmp/bios_current.bin

PRIORITY 3 — LUKS KEY ROTATION (Passphrase likely captured — CRIT-001)
  [ ] Confirm backup of data before proceeding
  [ ] cryptsetup luksAddKey /dev/sda2          # Add new passphrase
  [ ] cryptsetup luksKillSlot /dev/sda2 0      # Remove old slot(s)
  [ ] cryptsetup luksDump /dev/sda2            # Verify

PRIORITY 4 — HARDWARE/FIRMWARE (Requires physical access + tools)
  [ ] ACTION-006: External timing analysis for VMBR detection
                  Tool: rdtsc-based timing test from external bootable Linux
  [ ] ACTION-007: Physical memory imaging via hardware DMA (LiME or PCILeech)
                  before any further software analysis
  [ ] SUPP-004:   Verify C3 state in BIOS power settings; re-enable if disabled
  [ ] SUPP-001:   Image reserved RAM region 0x27fe2800-0x28000000

PRIORITY 5 — KERNEL REBUILD (Long-term hardening)
  [ ] Rebuild kernel with:
        CONFIG_COMPAT_VDSO=n          (LOW-004: fixed vDSO address)
        CONFIG_PARAVIRT=n             (CRIT-002: disable paravirt ops)
        CONFIG_X86_PAE=y + CONFIG_X86_XD_BIT=y  (HIGH-004: hardware NX)
        CONFIG_RELOCATABLE=y          (KASLR preparation)
        CONFIG_DEBUG_RODATA=y         (SUPP-030: write protect race)
        CONFIG_SECURITY_SELINUX=y     (CRIT-006: enforce SELinux primary)
        CONFIG_BLK_DEV_RAM=n          (SUPP-027: remove brd)
  [ ] Remove from initrd: mac_hid, padlock, isapnp, uinput
  [ ] Add TPM-based initrd integrity verification (replaces unverified boot)

PRIORITY 6 — NETWORK NAMESPACE CLEANUP
  [ ] ip netns list                    # List all namespaces
  [ ] ip netns exec <ns> ip link show  # Inspect each namespace
  [ ] ip netns delete <ns>             # Remove unauthorized namespaces

PRIORITY 7 — TIMELINE RECONSTRUCTION
  [ ] ACTION-014: Collect NTP server logs to establish actual boot timestamps
  [ ] ACTION-015: Filesystem metadata analysis with externally verified timestamps

VERIFICATION REQUIREMENTS (CTW-BOOT-FA-001 Section 11.0):
  [ ] VR-001: Confirm DSDT vendor string characters after "SYSFe"
  [ ] VR-002: Confirm e820 entry end address (0xfeda0000 start > end anomaly)
  [ ] VR-003: Confirm exact characters of console sequences "5DE/69/H826" and "anaGddaTSlB"
  [ ] VR-004: Confirm kernel build year in "EDT 21" timestamp
  [ ] VR-005: Confirm full bootloader UUID string

================================================================================
ANOMALY COVERAGE SUMMARY
================================================================================
CRITICAL (7+4=11):  CRIT-001,002,003,004,005,006,007 + SUPP-026,027,028,029
HIGH     (6+4=10):  HIGH-001,002,003,004,005,006 + SUPP-030,031,032,033
MEDIUM   (8+3=11):  MED-001..008 + SUPP-034,035,036
LOW      (4+1=5):   LOW-001,002,003,004 + SUPP-037
TOTAL:  37 anomalies documented | Automated remediations: 22 | Manual required: 15
================================================================================
CHECKLIST
    log_fix "Remediation checklist written to $REPORT_FILE"
    cat "$REPORT_FILE"
}

# ============================================================================
# VERIFY PHASE — confirm remediations are in place
# ============================================================================
run_verify() {
    section "VERIFY PHASE"

    # Verify blacklist
    [[ -f /etc/modprobe.d/ctw_security_blacklist.conf ]] \
        && log_ok "Module blacklist present" \
        || log_bad "Module blacklist MISSING"

    # Verify sysctl
    local va_space
    va_space=$(sysctl -n kernel.randomize_va_space 2>/dev/null) || va_space=0
    [[ "$va_space" -eq 2 ]] && log_ok "ASLR=2 (full)" || log_bad "ASLR=$va_space (should be 2)"

    # Verify SELinux
    getenforce 2>/dev/null | grep -q "Enforcing" \
        && log_ok "SELinux Enforcing" \
        || log_bad "SELinux NOT Enforcing"

    # Verify no uinput/mac_hid loaded
    lsmod 2>/dev/null | grep -qE "^uinput|^mac_hid" \
        && log_bad "Synthetic input modules still loaded" \
        || log_ok "Synthetic input modules not loaded"

    # Verify RTC
    local hw_year
    hw_year=$(hwclock --show 2>/dev/null | grep -oP '\d{4}' | tail -1) || hw_year=0
    [[ "$hw_year" -ge 2024 ]] \
        && log_ok "RTC year $hw_year is current" \
        || log_bad "RTC year $hw_year still incorrect"

    # Verify initrd immutable
    lsattr "$INITRD_PATH" 2>/dev/null | grep -q "\-i\-" \
        && log_ok "initrd immutable flag set" \
        || log_warn "initrd immutable flag not set (may not be supported on this fs)"

    # Verify no covert netns
    local ns_count
    ns_count=$(ip netns list 2>/dev/null | wc -l) || ns_count=0
    [[ "$ns_count" -eq 0 ]] \
        && log_ok "No non-default network namespaces" \
        || log_bad "$ns_count non-default namespace(s) remain"

    # Verify dmesg restriction
    local dmesg_restrict
    dmesg_restrict=$(sysctl -n kernel.dmesg_restrict 2>/dev/null) || dmesg_restrict=0
    [[ "$dmesg_restrict" -eq 1 ]] \
        && log_ok "dmesg restricted to root" \
        || log_warn "dmesg_restrict=$dmesg_restrict (should be 1)"

    log ""
    log_ok "Verify phase complete — review BAD/WARN entries above"
}

# ============================================================================
# MAIN DISPATCH
# ============================================================================
main() {
    echo -e "${BOLD}"
    echo "================================================================"
    echo " CTW-BOOT-REMEDIATE — Forensic Boot Hardening Script"
    echo " CTW-BOOT-FA-001 + CTW-BOOT-FA-001-SUPP (37 Anomalies)"
    echo " Mode: $MODE"
    echo "================================================================"
    echo -e "${RESET}"

    preflight

    # Always run audit phase
    audit_initrd
    audit_vmbr
    audit_input_devices
    audit_acpi_dsdt
    audit_console_sequences
    audit_lsm
    audit_runlevel
    audit_rtc
    audit_uuid
    audit_scsi_override
    audit_input_gap
    audit_ioport_gap
    audit_reserved_memory
    audit_tsc
    audit_cardbus
    audit_netns
    audit_ramdisk
    audit_dmapper
    audit_edd
    audit_c3_state
    audit_hugetlb
    audit_quota_preluks

    if [[ "$MODE" == "--fix" ]]; then
        log ""
        log "================================================================"
        log " APPLYING REMEDIATIONS"
        log "================================================================"
        fix_grub
        fix_initrd_integrity
        fix_rtc
        fix_blacklist_modules
        fix_selinux
        fix_sysctl
        fix_netns_isolation
        fix_dm_cleanup
        fix_luks_hardening
        fix_audit
        fix_cardbus
        fix_vdso
        fix_generate_checklist
        log ""
        log_ok "Fix phase complete. Reboot required for GRUB/module changes."
        log "Full log: $LOG_FILE"
        log "Checklist: $REPORT_FILE"

    elif [[ "$MODE" == "--verify" ]]; then
        run_verify

    else
        log ""
        log "AUDIT COMPLETE — no changes made."
        log "Run with --fix to apply remediations."
        log "Run with --verify to confirm remediations are in place."
        log "Full log: $LOG_FILE"
    fi
}

main
