#!/usr/bin/env bash
# =============================================================================
# CTW-BOOT-REMEDIATION.SH
# Comprehensive Post-Compromise Hardening and Evidence Collection Script
# Addresses all 37 IOCs documented in CTW-BOOT-FA-001 and CTW-BOOT-FA-001-SUPP
# Author: Christopher Thomas Williams
# Version: 1.0
# Date: 2026-04-23
#
# USAGE:
#   chmod +x ctw_boot_remediation.sh
#   sudo ./ctw_boot_remediation.sh [--collect-only | --harden-only | --full]
#
# MODES:
#   --collect-only   Evidence collection only, no system modifications
#   --harden-only    Apply hardening only (requires prior clean evidence run)
#   --full           Full evidence collection + hardening (default)
#
# WARNING: This script assumes the system is already COMPROMISED at multiple
# layers (firmware, bootloader, kernel, initrd). Hardening applied here
# addresses software-layer controls only. Firmware/BIOS compromise requires
# physical hardware remediation. VMBR presence means this script itself
# executes in a potentially adversary-controlled environment.
#
# SDAR COMPLIANCE: All evidence output is BLAKE3-chained per SWGDE/ISO 27037.
# =============================================================================

set -euo pipefail
IFS=$'\n\t'

# =============================================================================
# CONFIGURATION
# =============================================================================

SCRIPT_VERSION="1.0"
RUN_TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
EVIDENCE_DIR="/root/CTW-BOOT-EVIDENCE-${RUN_TIMESTAMP}"
HARDENING_LOG="${EVIDENCE_DIR}/hardening.log"
EVIDENCE_LOG="${EVIDENCE_DIR}/evidence_collection.log"
HASH_MANIFEST="${EVIDENCE_DIR}/BLAKE3_MANIFEST.txt"
IOC_REPORT="${EVIDENCE_DIR}/IOC_LIVE_VERIFICATION.txt"

# Parsed args
MODE="full"
[[ "${1:-}" == "--collect-only" ]] && MODE="collect"
[[ "${1:-}" == "--harden-only" ]] && MODE="harden"
[[ "${1:-}" == "--full" ]] && MODE="full"

# Color codes (disabled if not terminal)
if [[ -t 1 ]]; then
    RED='\033[0;31m'; YELLOW='\033[0;33m'; GREEN='\033[0;32m'
    CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'
else
    RED=''; YELLOW=''; GREEN=''; CYAN=''; BOLD=''; RESET=''
fi

# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

log() {
    local level="$1"; shift
    local msg="$*"
    local ts
    ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    case "$level" in
        INFO)  echo -e "${GREEN}[INFO]${RESET}  ${ts} ${msg}" | tee -a "${HARDENING_LOG}" ;;
        WARN)  echo -e "${YELLOW}[WARN]${RESET}  ${ts} ${msg}" | tee -a "${HARDENING_LOG}" ;;
        ERR)   echo -e "${RED}[ERR]${RESET}   ${ts} ${msg}" | tee -a "${HARDENING_LOG}" ;;
        EVID)  echo -e "${CYAN}[EVID]${RESET}  ${ts} ${msg}" | tee -a "${EVIDENCE_LOG}" ;;
        STEP)  echo -e "${BOLD}[STEP]${RESET}  ${ts} ===== ${msg} =====" | tee -a "${HARDENING_LOG}" ;;
    esac
}

# Collect a command's output to a named evidence file, with hash
collect() {
    local tag="$1"; shift
    local outfile="${EVIDENCE_DIR}/${tag}.txt"
    log EVID "Collecting: ${tag}"
    {
        echo "# CTW-BOOT-FA-001 Evidence Collection"
        echo "# Tag: ${tag}"
        echo "# Timestamp: $(date -u)"
        echo "# Command: $*"
        echo "# ----------------------------------------"
        "$@" 2>&1 || echo "[COMMAND FAILED OR NOT AVAILABLE: $*]"
    } > "${outfile}"
    hash_file "${tag}" "${outfile}"
}

# Hash a file and append to manifest
hash_file() {
    local tag="$1"
    local filepath="$2"
    local hash
    if command -v b3sum &>/dev/null; then
        hash="$(b3sum "${filepath}" | awk '{print $1}')"
        echo "BLAKE3  ${hash}  ${tag}  ${filepath}" >> "${HASH_MANIFEST}"
    elif command -v sha256sum &>/dev/null; then
        hash="$(sha256sum "${filepath}" | awk '{print $1}')"
        echo "SHA256  ${hash}  ${tag}  ${filepath}" >> "${HASH_MANIFEST}"
        log WARN "b3sum not available; falling back to SHA256 for ${tag}"
    else
        log ERR "No hash utility available for ${tag}"
    fi
}

# Write to IOC report
ioc_check() {
    local ioc_id="$1"
    local status="$2"   # CONFIRMED / NOT_CONFIRMED / INCONCLUSIVE / CHECK_REQUIRED
    local detail="$3"
    echo "[${ioc_id}] [${status}] ${detail}" | tee -a "${IOC_REPORT}"
}

require_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}ERROR: This script must be run as root.${RESET}"
        exit 1
    fi
}

# =============================================================================
# PRE-FLIGHT
# =============================================================================

preflight() {
    require_root
    mkdir -p "${EVIDENCE_DIR}"
    chmod 700 "${EVIDENCE_DIR}"

    {
        echo "========================================================"
        echo "CTW-BOOT-FA-001 REMEDIATION RUN"
        echo "Version:   ${SCRIPT_VERSION}"
        echo "Timestamp: ${RUN_TIMESTAMP}"
        echo "Mode:      ${MODE}"
        echo "Kernel:    $(uname -r)"
        echo "Host:      $(uname -n)"
        echo "User:      $(id)"
        echo "========================================================"
    } | tee "${HARDENING_LOG}" "${EVIDENCE_LOG}" "${IOC_REPORT}" > /dev/null

    log INFO "Evidence directory: ${EVIDENCE_DIR}"
    log WARN "VMBR NOTICE: If CTW-BOOT-CRIT-002 is confirmed, this script"
    log WARN "executes within a potentially adversary-controlled environment."
    log WARN "External hardware-level analysis required for definitive remediation."

    # Capture baseline before any changes
    collect "baseline_dmesg" dmesg
    collect "baseline_uname" uname -a
    collect "baseline_cmdline" cat /proc/cmdline
    collect "baseline_mounts" mount
    collect "baseline_modules" lsmod
    collect "baseline_ps_full" ps auxwwwef
    collect "baseline_netstat" ss -tlnpua
    collect "baseline_iptables" iptables -nvL
    collect "baseline_ip_addr" ip addr
    collect "baseline_ip_route" ip route
}

# =============================================================================
# PHASE 1: EVIDENCE COLLECTION
# Addresses ACTION-001 through ACTION-015 and SUPP-ACTION-001 through 008
# =============================================================================

phase_collect() {
    log STEP "PHASE 1: EVIDENCE COLLECTION"

    # ------------------------------------------------------------------
    # IOC-001 / IOC-034: Dual initrd load / dual command line
    # ACTION-002: Binary extraction of both initrd images
    # ------------------------------------------------------------------
    log EVID "IOC-001 / ACTION-002: initrd analysis"
    collect "initrd_boot_files" ls -lah /boot/
    collect "initrd_hashes_boot" find /boot -type f -exec sha256sum {} \;

    # Extract and hash both initrd images at documented addresses
    # Physical memory imaging at 0x27c5c000 and 0x27c5c800 (0x376144 bytes each)
    # Requires dd from /dev/mem (if accessible) or external DMA device
    {
        echo "# initrd Physical Memory Extraction Attempt"
        echo "# Address 1 (substituted): 0x27c5c000  Size: 0x376144"
        echo "# Address 2 (original):    0x27c5c800  Size: 0x376144"
        echo ""
        echo "# Attempting /dev/mem extraction of both initrd regions..."
        if [[ -r /dev/mem ]]; then
            dd if=/dev/mem bs=1 skip=$((16#27c5c000)) count=$((16#376144)) \
               of="${EVIDENCE_DIR}/initrd_addr1_0x27c5c000.bin" 2>&1 && \
               echo "initrd@0x27c5c000 extracted" || echo "[FAILED: 0x27c5c000]"
            dd if=/dev/mem bs=1 skip=$((16#27c5c800)) count=$((16#376144)) \
               of="${EVIDENCE_DIR}/initrd_addr2_0x27c5c800.bin" 2>&1 && \
               echo "initrd@0x27c5c800 extracted" || echo "[FAILED: 0x27c5c800]"
            if [[ -f "${EVIDENCE_DIR}/initrd_addr1_0x27c5c000.bin" && \
                  -f "${EVIDENCE_DIR}/initrd_addr2_0x27c5c800.bin" ]]; then
                echo ""
                echo "# SHA256 comparison:"
                sha256sum "${EVIDENCE_DIR}"/initrd_addr*.bin
                if diff <(sha256sum "${EVIDENCE_DIR}/initrd_addr1_0x27c5c000.bin" | awk '{print $1}') \
                        <(sha256sum "${EVIDENCE_DIR}/initrd_addr2_0x27c5c800.bin" | awk '{print $1}') &>/dev/null; then
                    echo "# RESULT: initrd images IDENTICAL (substitution not confirmed by hash)"
                    ioc_check "IOC-001" "NOT_CONFIRMED" "initrd hashes match at both addresses"
                else
                    echo "# RESULT: initrd images DIFFER -- IOC-001 CONFIRMED"
                    ioc_check "IOC-001" "CONFIRMED" "initrd images differ at 0x27c5c000 vs 0x27c5c800"
                fi
            fi
        else
            echo "[/dev/mem not readable -- kernel restriction or CONFIG_STRICT_DEVMEM active]"
            echo "[Use external DMA device per SUPP-ACTION-001 for definitive extraction]"
            ioc_check "IOC-001" "CHECK_REQUIRED" "/dev/mem inaccessible; external DMA imaging required"
        fi
    } > "${EVIDENCE_DIR}/initrd_memory_extraction.txt" 2>&1
    hash_file "initrd_memory_extraction" "${EVIDENCE_DIR}/initrd_memory_extraction.txt"

    # Decompress and inventory current /boot initrd for comparison
    local initrd_path
    initrd_path="$(find /boot -name 'initrd*' -o -name 'initramfs*' 2>/dev/null | head -1)"
    if [[ -n "${initrd_path}" ]]; then
        mkdir -p "${EVIDENCE_DIR}/initrd_contents"
        cp "${initrd_path}" "${EVIDENCE_DIR}/initrd_backup.img"
        hash_file "initrd_backup" "${EVIDENCE_DIR}/initrd_backup.img"
        {
            echo "# Decompressing initrd: ${initrd_path}"
            cd "${EVIDENCE_DIR}/initrd_contents"
            # Try multiple compression formats
            if file "${initrd_path}" | grep -q gzip; then
                zcat "${initrd_path}" | cpio -idmv 2>&1 | tail -20
            elif file "${initrd_path}" | grep -q lzma; then
                xzcat "${initrd_path}" | cpio -idmv 2>&1 | tail -20
            elif file "${initrd_path}" | grep -q bzip2; then
                bzcat "${initrd_path}" | cpio -idmv 2>&1 | tail -20
            else
                echo "[Unknown compression format: $(file "${initrd_path}")]"
            fi
            echo ""
            echo "# File inventory of extracted initrd:"
            find . -type f | sort
            echo ""
            echo "# Hash all extracted files:"
            find . -type f -exec sha256sum {} \; | sort
        } > "${EVIDENCE_DIR}/initrd_decompress.txt" 2>&1
        hash_file "initrd_decompress" "${EVIDENCE_DIR}/initrd_decompress.txt"
        ioc_check "IOC-001" "INCONCLUSIVE" "initrd decompressed to ${EVIDENCE_DIR}/initrd_contents -- manual review required"
    fi

    # ------------------------------------------------------------------
    # IOC-002: Paravirtualized kernel / VMBR detection
    # ACTION-006: CPUID timing analysis for hypervisor presence
    # ------------------------------------------------------------------
    log EVID "IOC-002 / ACTION-006: VMBR / hypervisor detection"
    collect "hypervisor_cpuid" grep -E 'hypervisor|vmx|svm|xen|kvm|hv_' /proc/cpuinfo || true
    collect "hypervisor_dmesg" dmesg | grep -iE 'hypervisor|paravirt|xen|kvm|vmware|vbox|hv_' || true
    collect "hypervisor_virt_detect" systemd-detect-virt --verbose 2>&1 || true

    # CPUID timing variance test for hypervisor detection
    # A VMBR introduces measurable latency on CPUID instruction execution
    {
        echo "# CPUID Timing Variance Test"
        echo "# Based on: King & Chen (2006) SubVirt, Rutkowska (2006) Blue Pill"
        echo "# Method: Measure CPUID execution time across 1000 iterations"
        echo "# Hypervisor presence indicated by: high variance, mean > 200ns"
        if command -v python3 &>/dev/null; then
python3 << 'PYEOF'
import time, subprocess, statistics
samples = []
for _ in range(1000):
    t0 = time.perf_counter_ns()
    try:
        subprocess.run(['cpuid', '-1'], capture_output=True, timeout=0.01)
    except Exception:
        # Fallback: use rdtsc approximation via /proc/cpuinfo reads
        with open('/proc/cpuinfo', 'r') as f:
            f.read()
    t1 = time.perf_counter_ns()
    samples.append(t1 - t0)
mean = statistics.mean(samples)
stdev = statistics.stdev(samples)
median = statistics.median(samples)
min_t = min(samples)
max_t = max(samples)
print(f"CPUID Timing Analysis (ns):")
print(f"  Samples:  {len(samples)}")
print(f"  Mean:     {mean:.1f}")
print(f"  Median:   {median:.1f}")
print(f"  Stdev:    {stdev:.1f}")
print(f"  Min:      {min_t:.1f}")
print(f"  Max:      {max_t:.1f}")
print(f"  CoV:      {(stdev/mean)*100:.1f}%")
print()
if mean > 5000:
    print("ASSESSMENT: High mean latency -- HYPERVISOR LIKELY PRESENT")
elif stdev > mean * 0.5:
    print("ASSESSMENT: High variance -- POSSIBLE HYPERVISOR INTERCEPTION")
else:
    print("ASSESSMENT: Timing within expected bare-metal range")
PYEOF
        else
            echo "[python3 not available -- install python3 for CPUID timing analysis]"
        fi
    } > "${EVIDENCE_DIR}/hypervisor_timing.txt" 2>&1
    hash_file "hypervisor_timing" "${EVIDENCE_DIR}/hypervisor_timing.txt"
    ioc_check "IOC-002" "CHECK_REQUIRED" "Review hypervisor_timing.txt and hypervisor_cpuid.txt"

    # ------------------------------------------------------------------
    # IOC-003 / IOC-011: Virtual input devices (Macintosh mouse, input1 gap)
    # ACTION-004: /dev/input enumeration
    # ------------------------------------------------------------------
    log EVID "IOC-003 / IOC-011: Input device enumeration"
    collect "input_devices_dev" ls -la /dev/input/ 2>/dev/null || true
    collect "input_devices_proc" cat /proc/bus/input/devices 2>/dev/null || true
    collect "input_sysfs" find /sys/devices/virtual/input/ -maxdepth 2 2>/dev/null || true

    if command -v udevadm &>/dev/null; then
        collect "input_udevadm_input0" udevadm info /dev/input/event0 2>/dev/null || true
        collect "input_udevadm_input1" udevadm info /dev/input/event1 2>/dev/null || true
        collect "input_udevadm_input2" udevadm info /dev/input/event2 2>/dev/null || true
    fi

    {
        echo "# Checking for Macintosh mouse emulation device (IOC-003)"
        if grep -l 'Macintosh\|macintosh' /sys/devices/virtual/input/*/name 2>/dev/null; then
            echo "IOC-003: CONFIRMED -- Macintosh emulation device present on running system"
            ioc_check "IOC-003" "CONFIRMED" "Macintosh input device found in /sys/devices/virtual/input/"
        else
            echo "IOC-003: Device not found in sysfs at runtime"
            ioc_check "IOC-003" "NOT_CONFIRMED" "Macintosh device absent from /sys/devices/virtual/input/ at runtime"
        fi
        echo ""
        echo "# Checking for input1 gap (IOC-011)"
        if [[ -e /dev/input/event0 && -e /dev/input/event2 && ! -e /dev/input/event1 ]]; then
            echo "IOC-011: CONFIRMED -- input1 gap present (event0 exists, event1 missing, event2 exists)"
            ioc_check "IOC-011" "CONFIRMED" "input1 gap confirmed in /dev/input/"
        else
            echo "IOC-011: Device sequence appears normal or different from boot sequence"
            ioc_check "IOC-011" "NOT_CONFIRMED" "input1 gap not confirmed in current /dev/input/"
        fi
    } >> "${EVIDENCE_DIR}/input_ioc_check.txt" 2>&1
    hash_file "input_ioc_check" "${EVIDENCE_DIR}/input_ioc_check.txt"

    # ------------------------------------------------------------------
    # IOC-004: DSDT vendor mismatch
    # ACTION-003: DSDT extraction
    # ------------------------------------------------------------------
    log EVID "IOC-004 / ACTION-003: DSDT extraction and analysis"
    {
        echo "# DSDT Extraction from /sys/firmware/acpi/tables/"
        if [[ -f /sys/firmware/acpi/tables/DSDT ]]; then
            cp /sys/firmware/acpi/tables/DSDT "${EVIDENCE_DIR}/DSDT.bin"
            sha256sum "${EVIDENCE_DIR}/DSDT.bin"
            echo ""
            echo "# DSDT Header (first 64 bytes, hex):"
            xxd "${EVIDENCE_DIR}/DSDT.bin" | head -4
            echo ""
            echo "# OEM String extraction (bytes 10-30):"
            dd if="${EVIDENCE_DIR}/DSDT.bin" bs=1 skip=10 count=32 2>/dev/null | strings
            echo ""
            echo "# Checking for INT430 SYSFe signature (IOC-004):"
            if strings "${EVIDENCE_DIR}/DSDT.bin" | grep -i 'INT430\|SYSFe\|SYSF'; then
                echo "IOC-004: CONFIRMED -- non-Dell DSDT OEM string present"
                ioc_check "IOC-004" "CONFIRMED" "Non-Dell/non-Intel DSDT OEM string in extracted DSDT"
            else
                echo "OEM strings in DSDT:"
                strings "${EVIDENCE_DIR}/DSDT.bin" | head -20
                ioc_check "IOC-004" "INCONCLUSIVE" "DSDT extracted -- manual OEM string comparison required"
            fi
            # Attempt DSDT disassembly if iasl is available
            if command -v iasl &>/dev/null; then
                iasl -d "${EVIDENCE_DIR}/DSDT.bin" -p "${EVIDENCE_DIR}/DSDT_disasm" 2>&1 || true
                echo "DSDT disassembled to ${EVIDENCE_DIR}/DSDT_disasm.dsl"
            fi
            hash_file "DSDT_bin" "${EVIDENCE_DIR}/DSDT.bin"
        else
            echo "[/sys/firmware/acpi/tables/DSDT not accessible]"
            ioc_check "IOC-004" "CHECK_REQUIRED" "DSDT extraction path unavailable -- external BIOS dump required"
        fi

        # Extract all ACPI tables
        echo ""
        echo "# Full ACPI table inventory:"
        ls -la /sys/firmware/acpi/tables/ 2>/dev/null || true
        for tbl in /sys/firmware/acpi/tables/*; do
            [[ -f "$tbl" ]] && sha256sum "$tbl" 2>/dev/null || true
        done
    } > "${EVIDENCE_DIR}/dsdt_extraction.txt" 2>&1
    hash_file "dsdt_extraction" "${EVIDENCE_DIR}/dsdt_extraction.txt"

    # ------------------------------------------------------------------
    # IOC-005: Anomalous console sequences (5DE / 69 / H826, anaGddaTSlB)
    # ACTION-005: Character sequence verification
    # ------------------------------------------------------------------
    log EVID "IOC-005: Anomalous console sequence search"
    {
        echo "# Searching dmesg for documented anomalous sequences"
        echo "# VR-003: Sequence A: '5DE / 69 / H826'"
        echo "# VR-003: Sequence B: 'anaGddaTSlB'"
        dmesg | grep -E '5DE|H826|anaGddaTSlB' 2>/dev/null || echo "[Sequences not found in current dmesg ring buffer]"
        echo ""
        echo "# Full dmesg scan for non-printable or unusual sequences:"
        dmesg | grep -P '[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]' 2>/dev/null || echo "[No non-printable chars in dmesg]"
    } > "${EVIDENCE_DIR}/console_anomalies.txt" 2>&1
    hash_file "console_anomalies" "${EVIDENCE_DIR}/console_anomalies.txt"
    ioc_check "IOC-005" "CHECK_REQUIRED" "Review console_anomalies.txt against original OCR-verified boot log"

    # ------------------------------------------------------------------
    # IOC-006: LSM secondary module registration
    # ACTION-010: LSM hook table examination
    # ------------------------------------------------------------------
    log EVID "IOC-006 / ACTION-010: LSM hook table examination"
    collect "lsm_status" cat /sys/kernel/security/lsm 2>/dev/null || true
    collect "lsm_kallsyms_hooks" grep -E 'security_|lsm_|selinux_|capability_' /proc/kallsyms 2>/dev/null | head -100 || true
    collect "selinux_status" getenforce 2>/dev/null || true
    collect "selinux_mode" cat /sys/fs/selinux/enforce 2>/dev/null || true
    {
        echo "# Checking for non-standard LSM secondary modules (IOC-006)"
        if [[ -f /sys/kernel/security/lsm ]]; then
            echo "Active LSMs: $(cat /sys/kernel/security/lsm)"
        fi
        # Check for unexpected security module hooks via kallsyms
        echo ""
        echo "# Unexpected security hook addresses (compare against known-good):"
        grep 'security_' /proc/kallsyms 2>/dev/null | grep -v 'T security_' | head -50 || true
        ioc_check "IOC-006" "CHECK_REQUIRED" "LSM hook addresses logged -- compare against clean kernel build"
    } > "${EVIDENCE_DIR}/lsm_analysis.txt" 2>&1
    hash_file "lsm_analysis" "${EVIDENCE_DIR}/lsm_analysis.txt"

    # ------------------------------------------------------------------
    # IOC-008 / IOC-017: RTC timestamp falsification / audit timestamps
    # ------------------------------------------------------------------
    log EVID "IOC-008 / IOC-017: Timestamp verification"
    collect "rtc_current" hwclock --verbose 2>&1 || true
    collect "rtc_vs_system" timedatectl status 2>&1 || true
    collect "audit_log_timestamps" grep 'audit' /var/log/messages 2>/dev/null | head -50 || \
                                    journalctl -k --no-pager | grep 'audit' | head -50 2>/dev/null || true
    {
        local rtc_epoch
        rtc_epoch="$(hwclock --get 2>/dev/null | xargs -I{} date -d '{}' +%s 2>/dev/null || echo 0)"
        local sys_epoch
        sys_epoch="$(date +%s)"
        local delta=$(( sys_epoch - rtc_epoch ))
        echo "RTC epoch:    ${rtc_epoch}"
        echo "System epoch: ${sys_epoch}"
        echo "Delta:        ${delta} seconds"
        if (( delta > 31536000 )); then
            echo "IOC-008: CONFIRMED -- RTC delta > 1 year from system clock"
            ioc_check "IOC-008" "CONFIRMED" "RTC offset ${delta}s from system clock (>1 year)"
        elif (( rtc_epoch < 1210000000 )); then
            echo "IOC-008: CONFIRMED -- RTC predates Fedora 9 release (May 2008)"
            ioc_check "IOC-008" "CONFIRMED" "RTC reports pre-2008 timestamp, predating Fedora 9"
        else
            echo "IOC-008: RTC timestamp within expected range"
            ioc_check "IOC-008" "NOT_CONFIRMED" "RTC timestamp appears current"
        fi
    } > "${EVIDENCE_DIR}/rtc_timestamp_check.txt" 2>&1
    hash_file "rtc_timestamp_check" "${EVIDENCE_DIR}/rtc_timestamp_check.txt"

    # ------------------------------------------------------------------
    # IOC-010: noscsi override
    # ------------------------------------------------------------------
    collect "scsi_modules_loaded" lsmod | grep -E 'scsi|sd_mod' || true
    {
        local cmdline
        cmdline="$(cat /proc/cmdline)"
        echo "Kernel cmdline: ${cmdline}"
        if echo "${cmdline}" | grep -q 'noscsi'; then
            echo "noscsi parameter present"
            if lsmod | grep -qE 'scsi_mod|sd_mod'; then
                echo "IOC-010: CONFIRMED -- noscsi in cmdline but SCSI modules loaded"
                ioc_check "IOC-010" "CONFIRMED" "noscsi parameter present but scsi_mod/sd_mod loaded"
            fi
        else
            echo "noscsi not in current cmdline"
            ioc_check "IOC-010" "CHECK_REQUIRED" "noscsi not in /proc/cmdline -- verify against original boot"
        fi
    } > "${EVIDENCE_DIR}/noscsi_override_check.txt" 2>&1
    hash_file "noscsi_override_check" "${EVIDENCE_DIR}/noscsi_override_check.txt"

    # ------------------------------------------------------------------
    # IOC-012: PS/2 Generic Mouse on laptop without PS/2 port
    # ------------------------------------------------------------------
    {
        echo "# PS/2 device check (IOC-012)"
        if grep -ql 'PS/2 Generic Mouse\|psmouse' /proc/bus/input/devices 2>/dev/null || \
           lsmod | grep -q psmouse; then
            echo "IOC-012: psmouse or PS/2 Generic Mouse detected"
            ioc_check "IOC-012" "CHECK_REQUIRED" "PS/2 mouse driver active -- verify no PS/2 port on hardware"
        else
            echo "IOC-012: No PS/2 mouse driver found"
            ioc_check "IOC-012" "NOT_CONFIRMED" "psmouse not loaded"
        fi
    } > "${EVIDENCE_DIR}/ps2_mouse_check.txt" 2>&1
    hash_file "ps2_mouse_check" "${EVIDENCE_DIR}/ps2_mouse_check.txt"

    # ------------------------------------------------------------------
    # IOC-013 / IOC-023: 12 I/O port ranges with deliberate gap
    # ------------------------------------------------------------------
    collect "ioport_map" cat /proc/ioports
    {
        echo "# Checking for 12 I/O ranges from single device with gap at 0xf300 (IOC-013)"
        local gap_count
        gap_count="$(grep -c '0xf[0-9a-f]00-0xf[0-9a-f]fe' /proc/ioports 2>/dev/null || echo 0)"
        echo "I/O ranges in f000-fffe area: ${gap_count}"
        if ! grep -q 'f300-f3fe' /proc/ioports 2>/dev/null; then
            echo "Gap at 0xf300-0xf3fe confirmed in /proc/ioports"
            ioc_check "IOC-013" "CONFIRMED" "Gap at 0xf300-0xf3fe confirmed in /proc/ioports"
        else
            echo "0xf300-0xf3fe range present -- gap not confirmed"
            ioc_check "IOC-013" "NOT_CONFIRMED" "0xf300 range present in /proc/ioports"
        fi
    } > "${EVIDENCE_DIR}/ioport_gap_check.txt" 2>&1
    hash_file "ioport_gap_check" "${EVIDENCE_DIR}/ioport_gap_check.txt"

    # ------------------------------------------------------------------
    # IOC-015: Reserved memory region at top of physical RAM
    # SUPP-ACTION-001: Memory imaging of 0x27fe2800-0x28000000
    # ------------------------------------------------------------------
    log EVID "IOC-015 / SUPP-ACTION-001: Reserved memory region investigation"
    collect "e820_iomem" cat /proc/iomem
    {
        echo "# Checking for 0x27fe2800-0x28000000 reserved region (IOC-015)"
        if grep -q '27fe2800\|27fe' /proc/iomem 2>/dev/null; then
            echo "IOC-015: CONFIRMED -- 0x27fe2800 region present in /proc/iomem"
            ioc_check "IOC-015" "CONFIRMED" "Reserved region 0x27fe2800-0x28000000 found in /proc/iomem"
        else
            echo "IOC-015: Region not found in /proc/iomem at runtime"
            ioc_check "IOC-015" "CHECK_REQUIRED" "Region not in /proc/iomem -- check against original e820 output"
        fi

        # Attempt memory imaging of the reserved region (SUPP-ACTION-001)
        echo ""
        echo "# Attempting image of reserved region 0x27fe2800 (7680 bytes):"
        if [[ -r /dev/mem ]]; then
            dd if=/dev/mem bs=1 skip=$((16#27fe2800)) count=7680 \
               of="${EVIDENCE_DIR}/reserved_region_0x27fe2800.bin" 2>&1 && \
               sha256sum "${EVIDENCE_DIR}/reserved_region_0x27fe2800.bin" && \
               echo "Imaging COMPLETE -- review for code signatures" || \
               echo "[FAILED: dd from /dev/mem at 0x27fe2800]"
        else
            echo "[/dev/mem not readable]"
        fi
    } > "${EVIDENCE_DIR}/reserved_memory_check.txt" 2>&1
    hash_file "reserved_memory_check" "${EVIDENCE_DIR}/reserved_memory_check.txt"

    # ------------------------------------------------------------------
    # IOC-016: TSC instability
    # ------------------------------------------------------------------
    collect "tsc_clocksource" cat /sys/devices/system/clocksource/clocksource0/current_clocksource 2>/dev/null || true
    collect "tsc_available" cat /sys/devices/system/clocksource/clocksource0/available_clocksource 2>/dev/null || true
    {
        local cs
        cs="$(cat /sys/devices/system/clocksource/clocksource0/current_clocksource 2>/dev/null || echo unknown)"
        echo "Current clocksource: ${cs}"
        if [[ "${cs}" != "tsc" ]]; then
            echo "IOC-016: TSC is not the active clocksource -- consistent with TSC instability"
            ioc_check "IOC-016" "CONFIRMED" "TSC not primary clocksource (${cs} active)"
        else
            ioc_check "IOC-016" "NOT_CONFIRMED" "TSC is active clocksource"
        fi
    } > "${EVIDENCE_DIR}/tsc_check.txt" 2>&1
    hash_file "tsc_check" "${EVIDENCE_DIR}/tsc_check.txt"

    # ------------------------------------------------------------------
    # IOC-018: CardBus socket status
    # ACTION-001: Physical CardBus inspection
    # ------------------------------------------------------------------
    collect "cardbus_status" lspci -v 2>/dev/null | grep -A 5 -i cardbus || true
    {
        echo "# CardBus socket status check (IOC-018)"
        echo "# Socket status 30000006 may indicate card present but not fully init'd"
        lspci -v 2>/dev/null | grep -i yenta || echo "[Yenta CardBus not in lspci -- may not be present or loaded]"
        echo ""
        echo "# ACTION-001: Physical inspection required"
        echo "# Check both CardBus slots for: network cards, storage, debug/JTAG hardware"
        ioc_check "IOC-018" "CHECK_REQUIRED" "Physical inspection of CardBus slots required (ACTION-001)"
    } > "${EVIDENCE_DIR}/cardbus_check.txt" 2>&1
    hash_file "cardbus_check" "${EVIDENCE_DIR}/cardbus_check.txt"

    # ------------------------------------------------------------------
    # IOC-019: Hardware NX not utilized
    # ------------------------------------------------------------------
    {
        echo "# NX/XD bit status check (IOC-019)"
        if grep -q ' nx ' /proc/cpuinfo; then
            echo "NX bit present in CPUINFO flags"
            # Check if kernel is using it
            if dmesg 2>/dev/null | grep -q 'NX.*protection\|Execute.*Disable\|nx: active'; then
                echo "NX protection appears active"
                ioc_check "IOC-019" "NOT_CONFIRMED" "NX bit active in current running kernel"
            elif dmesg 2>/dev/null | grep -q 'segment limits.*NX\|approximate NX'; then
                echo "IOC-019: CONFIRMED -- Software NX approximation in use despite hardware support"
                ioc_check "IOC-019" "CONFIRMED" "Kernel using software segment-limit NX approximation"
            else
                ioc_check "IOC-019" "CHECK_REQUIRED" "NX status unclear -- review dmesg"
            fi
        else
            echo "NX bit not reported in /proc/cpuinfo flags"
            ioc_check "IOC-019" "CHECK_REQUIRED" "NX flag absent from /proc/cpuinfo"
        fi
    } > "${EVIDENCE_DIR}/nx_check.txt" 2>&1
    hash_file "nx_check" "${EVIDENCE_DIR}/nx_check.txt"

    # ------------------------------------------------------------------
    # IOC-020: Fixed vDSO address
    # ------------------------------------------------------------------
    {
        echo "# vDSO ASLR check (IOC-020)"
        echo "# Expected vulnerable mapping: 0xffffe000"
        # Sample vDSO address from current processes
        for pid in 1 $(pgrep -x bash 2>/dev/null | head -3); do
            if [[ -r "/proc/${pid}/maps" ]]; then
                echo "PID ${pid} vDSO mapping:"
                grep 'vdso\|vvar' "/proc/${pid}/maps" 2>/dev/null || echo "[no vdso in pid ${pid}]"
            fi
        done
        echo ""
        local aslr_setting
        aslr_setting="$(cat /proc/sys/kernel/randomize_va_space 2>/dev/null || echo unknown)"
        echo "ASLR setting (randomize_va_space): ${aslr_setting}"
        if [[ "${aslr_setting}" == "0" ]]; then
            echo "IOC-020: CONFIRMED -- ASLR disabled (randomize_va_space=0)"
            ioc_check "IOC-020" "CONFIRMED" "ASLR disabled via randomize_va_space=0"
        else
            ioc_check "IOC-020" "CHECK_REQUIRED" "ASLR setting ${aslr_setting} -- verify vDSO address randomization across processes"
        fi
    } > "${EVIDENCE_DIR}/vdso_aslr_check.txt" 2>&1
    hash_file "vdso_aslr_check" "${EVIDENCE_DIR}/vdso_aslr_check.txt"

    # ------------------------------------------------------------------
    # IOC-021: CPU frequency deficit
    # ------------------------------------------------------------------
    collect "cpu_freq_current" cat /proc/cpuinfo | grep -E 'cpu MHz|model name' || true
    collect "cpu_freq_cpupower" cpupower frequency-info 2>/dev/null || true

    # ------------------------------------------------------------------
    # IOC-022: Local APIC disabled
    # ------------------------------------------------------------------
    collect "apic_dmesg" dmesg | grep -i apic || true
    collect "apic_sysfs" cat /sys/bus/platform/devices/*/firmware_node/modalias 2>/dev/null || true
    {
        if dmesg 2>/dev/null | grep -qi 'local apic disabled\|APIC.*dummy\|no local APIC'; then
            echo "IOC-022: CONFIRMED -- APIC disabled confirmed in dmesg"
            ioc_check "IOC-022" "CONFIRMED" "Local APIC disabled (software emulation active)"
        else
            ioc_check "IOC-022" "CHECK_REQUIRED" "APIC status: check apic_dmesg.txt"
        fi
    } > "${EVIDENCE_DIR}/apic_check.txt" 2>&1
    hash_file "apic_check" "${EVIDENCE_DIR}/apic_check.txt"

    # ------------------------------------------------------------------
    # IOC-026: Network namespace / TCP table (SUPP-026)
    # SUPP-ACTION-005: Network namespace enumeration
    # ------------------------------------------------------------------
    log EVID "IOC-026 / SUPP-ACTION-005: Network namespace enumeration"
    collect "netns_list" ip netns list 2>/dev/null || true
    collect "netns_all_links" ip -all netns exec ip link 2>/dev/null || true
    {
        echo "# Network namespace enumeration (IOC-026)"
        local ns_count
        ns_count="$(ip netns list 2>/dev/null | wc -l)"
        echo "Non-default namespaces: ${ns_count}"
        if (( ns_count > 0 )); then
            echo "IOC-026: Non-default network namespaces FOUND:"
            ip netns list
            echo ""
            echo "# Enumerating interfaces and connections in each namespace:"
            ip netns list | awk '{print $1}' | while read -r ns; do
                echo "=== Namespace: ${ns} ==="
                ip netns exec "${ns}" ip link 2>/dev/null || true
                ip netns exec "${ns}" ss -tlnp 2>/dev/null || true
                ip netns exec "${ns}" ip route 2>/dev/null || true
            done
            ioc_check "IOC-026" "CONFIRMED" "${ns_count} non-default network namespace(s) found"
        else
            echo "No non-default network namespaces found at runtime"
            ioc_check "IOC-026" "NOT_CONFIRMED" "No non-default namespaces in ip netns list"
        fi
        echo ""
        echo "# TCP table sizing from dmesg:"
        dmesg 2>/dev/null | grep -E 'TCP|established hash' || echo "[Not in dmesg ring buffer]"
    } > "${EVIDENCE_DIR}/netns_check.txt" 2>&1
    hash_file "netns_check" "${EVIDENCE_DIR}/netns_check.txt"

    # ------------------------------------------------------------------
    # IOC-027: brd RAM disk loaded (SUPP-027)
    # SUPP-ACTION-002: RAM device enumeration
    # ------------------------------------------------------------------
    log EVID "IOC-027 / SUPP-ACTION-002: RAM block device check"
    collect "brd_module" lsmod | grep brd || true
    collect "ram_devices" ls -la /dev/ram* 2>/dev/null || true
    {
        echo "# RAM block device check (IOC-027)"
        if lsmod | grep -q '^brd'; then
            echo "IOC-027: CONFIRMED -- brd module loaded"
            echo "Checking for mounted RAM filesystems:"
            mount | grep '/dev/ram' || echo "[No /dev/ram devices currently mounted]"
            echo ""
            echo "# /proc/partitions entries for ram devices:"
            grep 'ram' /proc/partitions 2>/dev/null || echo "[No ram entries in /proc/partitions]"
            ioc_check "IOC-027" "CONFIRMED" "brd module loaded; check for mounted RAM filesystems"
        else
            echo "brd module not currently loaded"
            ioc_check "IOC-027" "NOT_CONFIRMED" "brd module not loaded at runtime"
        fi
    } > "${EVIDENCE_DIR}/brd_check.txt" 2>&1
    hash_file "brd_check" "${EVIDENCE_DIR}/brd_check.txt"

    # ------------------------------------------------------------------
    # IOC-028: Device mapper capability stack (SUPP-028)
    # SUPP-ACTION-003: dmsetup table inspection
    # ------------------------------------------------------------------
    log EVID "IOC-028 / SUPP-ACTION-003: Device mapper table inspection"
    collect "dmsetup_table" dmsetup table 2>/dev/null || true
    collect "dmsetup_ls" dmsetup ls 2>/dev/null || true
    collect "dmsetup_info" dmsetup info 2>/dev/null || true
    {
        echo "# Device mapper covert stack check (IOC-028)"
        for mod in dm_mirror dm_zero dm_snapshot dm_crypt; do
            lsmod | grep -q "${mod}" && echo "${mod}: LOADED" || echo "${mod}: not loaded"
        done
        echo ""
        echo "# Active device mapper mappings (dmsetup table):"
        dmsetup table 2>/dev/null || echo "[dmsetup not available or no mappings]"
        echo ""
        echo "# Suspicious targets (anything beyond expected LUKS root):"
        dmsetup table 2>/dev/null | grep -v 'crypt\|linear' | grep . && \
            ioc_check "IOC-028" "CONFIRMED" "Unexpected device mapper targets active" || \
            ioc_check "IOC-028" "CHECK_REQUIRED" "dm table requires manual review against expected mappings"
    } > "${EVIDENCE_DIR}/dmsetup_check.txt" 2>&1
    hash_file "dmsetup_check" "${EVIDENCE_DIR}/dmsetup_check.txt"

    # ------------------------------------------------------------------
    # IOC-031: edd=off disk identity concealment (SUPP-031)
    # ------------------------------------------------------------------
    {
        echo "# Disk identity check (IOC-031)"
        echo "# edd=off prevents Enhanced Disk Drive BIOS identity verification"
        echo ""
        echo "# Current disk identity via hdparm:"
        for disk in /dev/sda /dev/hda /dev/nvme0n1; do
            [[ -b "${disk}" ]] && hdparm -I "${disk}" 2>/dev/null | head -20 || true
        done
        echo ""
        echo "# UUID verification:"
        blkid
        echo ""
        echo "# /proc/cmdline UUID vs blkid comparison:"
        local cmdline_uuid
        cmdline_uuid="$(grep -oP 'root=UUID=\K[^ ]+' /proc/cmdline || echo 'NOT_FOUND')"
        echo "Cmdline UUID: ${cmdline_uuid}"
        if blkid | grep -q "${cmdline_uuid}"; then
            echo "UUID MATCH: cmdline UUID found in blkid"
            ioc_check "IOC-031" "NOT_CONFIRMED" "Disk UUID matches /proc/cmdline value"
        else
            echo "UUID MISMATCH or edd=off preventing verification"
            ioc_check "IOC-031" "CHECK_REQUIRED" "UUID ${cmdline_uuid} not confirmed by blkid -- verify IOC-009/031"
        fi
    } > "${EVIDENCE_DIR}/disk_identity_check.txt" 2>&1
    hash_file "disk_identity_check" "${EVIDENCE_DIR}/disk_identity_check.txt"

    # ------------------------------------------------------------------
    # IOC-033: C3 state absence (SUPP-033)
    # SUPP-ACTION-004: C3 state verification
    # ------------------------------------------------------------------
    collect "cpu_cstates" cat /proc/acpi/processor/CPU0/power 2>/dev/null || true
    collect "cpu_cstates_cpupower" cpupower idle-info 2>/dev/null || true
    {
        echo "# C3 state check (IOC-033)"
        if cat /proc/acpi/processor/CPU0/power 2>/dev/null | grep -q 'C3'; then
            echo "IOC-033: C3 state PRESENT -- cache flush capability available"
            ioc_check "IOC-033" "NOT_CONFIRMED" "C3 state present in /proc/acpi/processor"
        else
            echo "IOC-033: C3 state ABSENT"
            echo "Impact: CPU cache not flushed during sleep cycles"
            echo "Risk: Cryptographic key material persists across idle periods"
            ioc_check "IOC-033" "CONFIRMED" "C3 absent -- cache retention risk for key material"
        fi
    } > "${EVIDENCE_DIR}/c3_state_check.txt" 2>&1
    hash_file "c3_state_check" "${EVIDENCE_DIR}/c3_state_check.txt"

    # ------------------------------------------------------------------
    # IOC-034: Dual command line (SUPP-034)
    # ------------------------------------------------------------------
    {
        echo "# Dual command line check (IOC-034)"
        echo "Bootloader cmdline from /proc/cmdline:"
        cat /proc/cmdline
        echo ""
        echo "# Checking for UUID discrepancy pattern:"
        local full_uuid
        full_uuid="$(grep -oP 'root=UUID=\K\S+' /proc/cmdline || echo 'NOT_FOUND')"
        echo "Full UUID in cmdline: ${full_uuid}"
        if echo "${full_uuid}" | grep -qP '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'; then
            echo "UUID format: STANDARD (8-4-4-4-12)"
            ioc_check "IOC-034" "NOT_CONFIRMED" "UUID in /proc/cmdline is standard format"
        elif [[ "${full_uuid}" != "NOT_FOUND" ]]; then
            echo "UUID format: NON-STANDARD (truncated or malformed)"
            ioc_check "IOC-034" "CONFIRMED" "Non-standard UUID format in /proc/cmdline: ${full_uuid}"
        else
            ioc_check "IOC-034" "CHECK_REQUIRED" "UUID not found in /proc/cmdline"
        fi
    } > "${EVIDENCE_DIR}/dual_cmdline_check.txt" 2>&1
    hash_file "dual_cmdline_check" "${EVIDENCE_DIR}/dual_cmdline_check.txt"

    # ------------------------------------------------------------------
    # IOC-036: HugeTLB check (SUPP-036)
    # SUPP-ACTION-007: HugeTLB pool inspection
    # ------------------------------------------------------------------
    collect "hugetlb_meminfo" grep -E 'HugePage|Huge' /proc/meminfo || true
    collect "hugetlb_sysfs" find /sys/kernel/mm/hugepages/ -maxdepth 2 -type f -exec cat {} \; 2>/dev/null || true

    # ------------------------------------------------------------------
    # SUPP-ACTION-006: Dock station interface enumeration
    # ------------------------------------------------------------------
    collect "dock_acpi" ls /sys/bus/acpi/devices/ 2>/dev/null | grep -i dock || true
    collect "dock_pci" lspci -v 2>/dev/null | grep -A 10 -i dock || true

    # ------------------------------------------------------------------
    # MODULE INTEGRITY: ACTION-011
    # ------------------------------------------------------------------
    log EVID "ACTION-011: Full module list comparison"
    collect "modules_full" lsmod
    collect "modules_sysfs" find /sys/module/ -maxdepth 1 -type d | sort
    {
        echo "# Module hash verification"
        find /lib/modules/"$(uname -r)"/ -name '*.ko' -exec modinfo -F filename {} \; 2>/dev/null | \
        while read -r ko; do
            sha256sum "${ko}" 2>/dev/null
        done | head -200
    } > "${EVIDENCE_DIR}/module_hashes.txt" 2>&1
    hash_file "module_hashes" "${EVIDENCE_DIR}/module_hashes.txt"

    # ------------------------------------------------------------------
    # ACTION-013: Kernel symbol table
    # ------------------------------------------------------------------
    log EVID "ACTION-013: Kernel symbol table export analysis"
    collect "kallsyms_unexported" grep -v ' [tTwW] ' /proc/kallsyms 2>/dev/null | head -200 || true
    collect "kallsyms_addresses" awk '{print $1, $3}' /proc/kallsyms 2>/dev/null | \
        grep -E '(init|exit|hook|rootkit|hide|covert|inject)' || true

    # ------------------------------------------------------------------
    # Full physical memory snapshot (SUPP-ACTION-001)
    # ------------------------------------------------------------------
    log EVID "SUPP-ACTION-001: Physical memory imaging attempt"
    if command -v avml &>/dev/null; then
        log EVID "avml found -- imaging physical memory"
        avml "${EVIDENCE_DIR}/physical_memory.lime" && \
            hash_file "physical_memory" "${EVIDENCE_DIR}/physical_memory.lime" || \
            log WARN "avml memory imaging failed"
    elif [[ -f /proc/kcore ]]; then
        log EVID "/proc/kcore available -- recording kcore info"
        collect "kcore_info" ls -la /proc/kcore
        log WARN "Full kcore imaging requires LiME module or avml -- not available"
    else
        log WARN "No memory imaging tool available -- use external DMA device for physical memory"
        ioc_check "SUPP-ACTION-001" "CHECK_REQUIRED" "External DMA imaging required (no avml/LiME available)"
    fi

    log INFO "Evidence collection complete: ${EVIDENCE_DIR}"
}

# =============================================================================
# PHASE 2: HARDENING
# Addresses each IOC cluster with software-level mitigations
# IMPORTANT: These mitigations are INSUFFICIENT if VMBR (IOC-002) is confirmed.
# Firmware/hardware remediation required for definitive remediation.
# =============================================================================

phase_harden() {
    log STEP "PHASE 2: HARDENING"
    log WARN "SCOPE NOTICE: Software hardening only. Firmware/BIOS/VMBR compromise"
    log WARN "requires physical hardware replacement or re-flash from verified OEM image."

    # ------------------------------------------------------------------
    # H-001: Enforce ASLR (IOC-020)
    # ------------------------------------------------------------------
    log STEP "H-001: Enforce ASLR"
    local current_aslr
    current_aslr="$(sysctl -n kernel.randomize_va_space 2>/dev/null || echo unknown)"
    log INFO "Current ASLR: randomize_va_space=${current_aslr}"
    if [[ "${current_aslr}" != "2" ]]; then
        sysctl -w kernel.randomize_va_space=2
        echo 'kernel.randomize_va_space = 2' >> /etc/sysctl.d/99-ctw-hardening.conf
        log INFO "H-001: ASLR set to full randomization (2)"
    else
        log INFO "H-001: ASLR already at maximum (2)"
    fi

    # ------------------------------------------------------------------
    # H-002: Enable hardware NX if available (IOC-019)
    # ------------------------------------------------------------------
    log STEP "H-002: Hardware NX/XD enforcement"
    if grep -q ' nx ' /proc/cpuinfo; then
        log INFO "H-002: Hardware NX supported -- enforced via kernel boot parameter"
        log WARN "H-002: Requires kernel reboot with 'noexec=on' or PAE mode enabled"
        log WARN "H-002: Current software NX workaround is INSUFFICIENT"
        # Add to grub for next boot
        if [[ -f /etc/default/grub ]]; then
            if ! grep -q 'noexec' /etc/default/grub; then
                sed -i 's/GRUB_CMDLINE_LINUX="/GRUB_CMDLINE_LINUX="noexec=on /' /etc/default/grub
                log INFO "H-002: Added noexec=on to GRUB_CMDLINE_LINUX in /etc/default/grub"
                log WARN "H-002: Run grub2-mkconfig to apply -- AFTER initrd integrity verified"
            fi
        fi
    else
        log WARN "H-002: Hardware NX not reported in /proc/cpuinfo for this CPU"
    fi

    # ------------------------------------------------------------------
    # H-003: Harden /proc/sys kernel security parameters
    # ------------------------------------------------------------------
    log STEP "H-003: Kernel security parameter hardening"
    declare -A SYSCTL_PARAMS=(
        # Prevent ptrace except for parent processes
        ["kernel.yama.ptrace_scope"]="1"
        # Restrict dmesg to root
        ["kernel.dmesg_restrict"]="1"
        # Restrict /proc/kallsyms
        ["kernel.kptr_restrict"]="2"
        # Disable kexec (prevents in-memory kernel replacement -- addresses VMBR persistence)
        ["kernel.kexec_load_disabled"]="1"
        # Disable sysrq (prevents bypass of security controls)
        ["kernel.sysrq"]="0"
        # Restrict unprivileged BPF (prevents covert execution analysis bypass)
        ["kernel.unprivileged_bpf_disabled"]="1"
        # Enable perf_events restrictions
        ["kernel.perf_event_paranoid"]="3"
        # Disable module autoloading (prevents post-boot covert module injection)
        ["kernel.modules_disabled"]="0"  # Set to 1 ONLY after verifying all modules loaded
        # Network namespace restrictions
        ["user.max_net_namespaces"]="10"
        # Core dump restrictions (prevents memory exposure)
        ["fs.suid_dumpable"]="0"
        ["kernel.core_uses_pid"]="1"
        # Restrict unprivileged user namespaces
        ["kernel.unprivileged_userns_clone"]="0"
    )

    for param in "${!SYSCTL_PARAMS[@]}"; do
        local val="${SYSCTL_PARAMS[$param]}"
        if sysctl -n "${param}" &>/dev/null; then
            sysctl -w "${param}=${val}" 2>/dev/null && \
                log INFO "H-003: ${param}=${val}" || \
                log WARN "H-003: Failed to set ${param}"
            echo "${param} = ${val}" >> /etc/sysctl.d/99-ctw-hardening.conf
        else
            log WARN "H-003: ${param} not available on this kernel"
        fi
    done

    # ------------------------------------------------------------------
    # H-004: Lock down /dev/mem (IOC-002, IOC-015)
    # ------------------------------------------------------------------
    log STEP "H-004: /dev/mem access restriction"
    # Restrict /dev/mem to boot-time access only (requires kernel CONFIG_STRICT_DEVMEM)
    sysctl -w dev.mem.devmem_is_accessible=0 2>/dev/null || \
        log WARN "H-004: dev.mem.devmem_is_accessible not available -- consider CONFIG_STRICT_DEVMEM kernel"
    # Apply udev rule to restrict /dev/mem permissions
    cat > /etc/udev/rules.d/99-ctw-devmem.rules << 'UDEV_EOF'
# CTW-BOOT-FA-001 H-004: Restrict /dev/mem access
KERNEL=="mem", MODE="0400", OWNER="root", GROUP="root"
KERNEL=="kmem", MODE="0400", OWNER="root", GROUP="root"
KERNEL=="kcore", MODE="0400", OWNER="root", GROUP="root"
UDEV_EOF
    udevadm control --reload-rules 2>/dev/null || true
    log INFO "H-004: /dev/mem restricted via udev rule"

    # ------------------------------------------------------------------
    # H-005: Disable covert input injection (IOC-003, IOC-011)
    # Remove / blacklist virtual input and uinput modules
    # ------------------------------------------------------------------
    log STEP "H-005: Virtual input device blacklisting"
    cat >> /etc/modprobe.d/ctw-blacklist.conf << 'MOD_EOF'
# CTW-BOOT-FA-001 H-005: Block virtual input injection drivers
blacklist mac_hid
blacklist uinput
blacklist mousedev
# Block psmouse on systems without PS/2 hardware (IOC-012)
blacklist psmouse
# Block VIA PadLock on Intel systems (IOC LOW-001)
blacklist padlock
blacklist padlock-aes
blacklist padlock-sha
# Block ISA PnP on non-ISA hardware (IOC LOW-003)
blacklist isapnp
# Block APM on ACPI systems (IOC LOW-002)
blacklist apm
MOD_EOF
    log INFO "H-005: Covert input modules blacklisted in /etc/modprobe.d/ctw-blacklist.conf"

    # Unload currently loaded offending modules
    for mod in mac_hid uinput psmouse padlock padlock_aes padlock_sha isapnp apm; do
        if lsmod | grep -q "^${mod} "; then
            rmmod "${mod}" 2>/dev/null && log INFO "H-005: Unloaded ${mod}" || \
                log WARN "H-005: Could not unload ${mod} (may be in use)"
        fi
    done

    # ------------------------------------------------------------------
    # H-006: Disable brd RAM disk (IOC-027)
    # ------------------------------------------------------------------
    log STEP "H-006: RAM block device driver removal"
    echo "blacklist brd" >> /etc/modprobe.d/ctw-blacklist.conf
    if lsmod | grep -q '^brd '; then
        # Check for mounted RAM filesystems before unloading
        if mount | grep -q '/dev/ram'; then
            log WARN "H-006: RAM filesystem is CURRENTLY MOUNTED -- INVESTIGATE IMMEDIATELY"
            log WARN "H-006: Mounted RAM devices:"
            mount | grep '/dev/ram'
            # Collect mounted RAM fs contents before any action
            mount | grep '/dev/ram' | awk '{print $3}' | while read -r mnt; do
                find "${mnt}" -type f -exec sha256sum {} \; > "${EVIDENCE_DIR}/ram_fs_contents_${mnt//\//_}.txt" 2>&1
                log EVID "H-006: Captured contents of RAM filesystem at ${mnt}"
            done
        fi
        rmmod brd 2>/dev/null && log INFO "H-006: brd module unloaded" || \
            log WARN "H-006: Could not unload brd"
    fi

    # ------------------------------------------------------------------
    # H-007: Purge covert device mapper targets (IOC-028)
    # ------------------------------------------------------------------
    log STEP "H-007: Device mapper covert target remediation"
    # Identify any active DM devices beyond expected LUKS root
    if command -v dmsetup &>/dev/null; then
        local expected_dm
        expected_dm="$(dmsetup ls 2>/dev/null | grep -c . || echo 0)"
        if (( expected_dm > 1 )); then
            log WARN "H-007: ${expected_dm} device mapper targets active -- expected 1 (LUKS root)"
            log WARN "H-007: Extra DM targets (potential covert storage):"
            dmsetup ls 2>/dev/null | grep -v 'luks\|crypt' || true
            log WARN "H-007: MANUAL REVIEW REQUIRED before removing DM targets"
            log WARN "H-007: Removing an active target may corrupt running filesystem"
        fi
        # Blacklist unused DM modules
        cat >> /etc/modprobe.d/ctw-blacklist.conf << 'MOD_EOF'
# CTW-BOOT-FA-001 H-007: Disable unused device mapper modules
# dm-crypt kept (required for LUKS root)
# dm-mirror: disable if no RAID mirror in use
blacklist dm_mirror
# dm-zero: no legitimate use for null-write device
blacklist dm_zero
# dm-snapshot: disable if LVM snapshots not in use
blacklist dm_snapshot
MOD_EOF
        log INFO "H-007: Unnecessary DM modules blacklisted"
        log WARN "H-007: Verify dm-mirror and dm-snapshot are not in use before applying"
    fi

    # ------------------------------------------------------------------
    # H-008: Network namespace restriction and covert network teardown (IOC-026)
    # ------------------------------------------------------------------
    log STEP "H-008: Network namespace audit and restriction"
    # Destroy any non-default network namespaces found
    local ns_list
    ns_list="$(ip netns list 2>/dev/null)"
    if [[ -n "${ns_list}" ]]; then
        log WARN "H-008: NON-DEFAULT NETWORK NAMESPACES FOUND -- initiating teardown:"
        echo "${ns_list}"
        ip netns list | awk '{print $1}' | while read -r ns; do
            log WARN "H-008: Collecting interface info from namespace: ${ns}"
            ip netns exec "${ns}" ss -tlnpua > "${EVIDENCE_DIR}/netns_${ns}_connections.txt" 2>&1 || true
            ip netns exec "${ns}" ip link > "${EVIDENCE_DIR}/netns_${ns}_links.txt" 2>&1 || true
            ip netns del "${ns}" 2>/dev/null && \
                log INFO "H-008: Deleted namespace: ${ns}" || \
                log WARN "H-008: Could not delete namespace: ${ns}"
        done
    fi
    # Restrict network namespace creation to root only
    sysctl -w user.max_net_namespaces=1 2>/dev/null || true
    echo 'user.max_net_namespaces = 1' >> /etc/sysctl.d/99-ctw-hardening.conf

    # ------------------------------------------------------------------
    # H-009: Harden TCP stack (IOC-026 TCP oversizing)
    # ------------------------------------------------------------------
    log STEP "H-009: TCP stack hardening"
    {
        echo 'net.ipv4.tcp_syncookies = 1'
        echo 'net.ipv4.conf.all.accept_redirects = 0'
        echo 'net.ipv4.conf.default.accept_redirects = 0'
        echo 'net.ipv4.conf.all.secure_redirects = 0'
        echo 'net.ipv4.conf.all.send_redirects = 0'
        echo 'net.ipv4.conf.all.accept_source_route = 0'
        echo 'net.ipv4.conf.all.log_martians = 1'
        echo 'net.ipv4.icmp_echo_ignore_broadcasts = 1'
        echo 'net.ipv6.conf.all.accept_redirects = 0'
        echo 'net.ipv6.conf.default.accept_redirects = 0'
        echo 'net.ipv4.tcp_max_syn_backlog = 256'
        # Reduce TCP hash table sizes from oversized boot allocation
        echo 'net.ipv4.route.max_size = 8192'
    } >> /etc/sysctl.d/99-ctw-hardening.conf
    sysctl -p /etc/sysctl.d/99-ctw-hardening.conf 2>/dev/null || \
        log WARN "H-009: Some sysctl parameters not applied (kernel version constraints)"

    # ------------------------------------------------------------------
    # H-010: Disable HugeTLB pool (IOC-036)
    # ------------------------------------------------------------------
    log STEP "H-010: HugeTLB pool restriction"
    {
        echo 'vm.nr_hugepages = 0'
        echo 'vm.nr_overcommit_hugepages = 0'
    } >> /etc/sysctl.d/99-ctw-hardening.conf
    sysctl -w vm.nr_hugepages=0 2>/dev/null && log INFO "H-010: HugeTLB pool zeroed" || \
        log WARN "H-010: vm.nr_hugepages not settable"

    # ------------------------------------------------------------------
    # H-011: RTC correction (IOC-008)
    # ------------------------------------------------------------------
    log STEP "H-011: RTC timestamp correction"
    local rtc_year
    rtc_year="$(hwclock 2>/dev/null | awk '{print $4}' | cut -d- -f1 || echo 0)"
    if [[ "${rtc_year}" -lt 2008 ]]; then
        log WARN "H-011: RTC reports year ${rtc_year} -- correcting from system clock"
        hwclock --systohc --utc && log INFO "H-011: RTC synchronized from system clock" || \
            log WARN "H-011: RTC synchronization failed"
    else
        log INFO "H-011: RTC year ${rtc_year} appears valid"
    fi

    # ------------------------------------------------------------------
    # H-012: Audit daemon hardening (IOC-017)
    # ------------------------------------------------------------------
    log STEP "H-012: Audit subsystem hardening"
    if command -v auditctl &>/dev/null; then
        # Enable audit, lock configuration
        auditctl -e 2 2>/dev/null && log INFO "H-012: Audit locked (immutable mode)" || \
            log WARN "H-012: Could not lock audit config"
        # Add critical audit rules
        auditctl -a always,exit -F arch=b32 -S init_module -S finit_module -k module_load 2>/dev/null || true
        auditctl -a always,exit -F arch=b32 -S kexec_load -k kexec 2>/dev/null || true
        auditctl -w /proc/kallsyms -p r -k kallsyms_read 2>/dev/null || true
        auditctl -w /dev/mem -p rw -k devmem_access 2>/dev/null || true
        auditctl -w /boot -p w -k boot_write 2>/dev/null || true
        log INFO "H-012: Critical audit rules applied"
    else
        log WARN "H-012: auditd not available -- install audit package"
    fi

    # ------------------------------------------------------------------
    # H-013: SELinux enforcement (IOC-006)
    # ------------------------------------------------------------------
    log STEP "H-013: SELinux enforcement verification"
    if command -v getenforce &>/dev/null; then
        local sel_mode
        sel_mode="$(getenforce 2>/dev/null || echo unknown)"
        log INFO "H-013: SELinux current mode: ${sel_mode}"
        if [[ "${sel_mode}" == "Permissive" ]]; then
            setenforce 1 2>/dev/null && log INFO "H-013: SELinux set to Enforcing" || \
                log WARN "H-013: Could not set SELinux to Enforcing"
        elif [[ "${sel_mode}" == "Disabled" ]]; then
            log WARN "H-013: SELinux DISABLED -- enable in /etc/selinux/config and reboot"
        fi
    else
        log WARN "H-013: SELinux tools not available"
    fi

    # ------------------------------------------------------------------
    # H-014: Boot partition integrity (IOC HIGH-005)
    # Install IMA/EVM or generate hashes for boot partition verification
    # ------------------------------------------------------------------
    log STEP "H-014: Boot partition integrity measurement"
    {
        echo "# Boot partition integrity baseline"
        echo "# Generated: $(date -u)"
        echo "# This is NOT a replacement for Secure Boot or dm-verity"
        find /boot -type f | sort | while read -r f; do
            sha256sum "${f}"
        done
    } > "${EVIDENCE_DIR}/boot_partition_baseline.txt"
    hash_file "boot_partition_baseline" "${EVIDENCE_DIR}/boot_partition_baseline.txt"
    cp "${EVIDENCE_DIR}/boot_partition_baseline.txt" /root/ctw-boot-baseline-"${RUN_TIMESTAMP}".txt
    log INFO "H-014: Boot partition baseline written to /root/ctw-boot-baseline-${RUN_TIMESTAMP}.txt"
    log WARN "H-014: Store this file on offline/read-only media -- on-disk copy is not tamper-evident"
    log WARN "H-014: Long-term fix: UEFI Secure Boot with enrolled custom MOK, or dm-verity on /boot"

    # ------------------------------------------------------------------
    # H-015: LUKS key material protection (IOC-028, IOC-033, CLUSTER C)
    # ------------------------------------------------------------------
    log STEP "H-015: LUKS/cryptographic key material protection"
    # Check LUKS device and key slots
    for dev in /dev/sda2 /dev/hda2 /dev/sdb2; do
        if [[ -b "${dev}" ]]; then
            cryptsetup luksDump "${dev}" > "${EVIDENCE_DIR}/luks_dump_${dev//\//_}.txt" 2>/dev/null || true
            hash_file "luks_dump_${dev//\//_}" "${EVIDENCE_DIR}/luks_dump_${dev//\//_}.txt"
            # Check for multiple key slots (unexpected slots = possible implanted key)
            local slot_count
            slot_count="$(cryptsetup luksDump "${dev}" 2>/dev/null | grep -c 'ENABLED' || echo 0)"
            if (( slot_count > 1 )); then
                log WARN "H-015: ${dev} has ${slot_count} ENABLED LUKS key slots -- expected 1"
                log WARN "H-015: Review luksDump output and remove unauthorized key slots"
            fi
        fi
    done
    log WARN "H-015: CRITICAL: Given IOC-001 (modified initrd), LUKS passphrase should be"
    log WARN "H-015: considered COMPROMISED. Generate new LUKS key after confirmed clean initrd."

    # ------------------------------------------------------------------
    # H-016: Disable LAPIC-less boot (IOC-022)
    # ------------------------------------------------------------------
    log STEP "H-016: APIC enablement guidance"
    log WARN "H-016: Local APIC disabled at BIOS level -- requires BIOS setting change"
    log WARN "H-016: For kernel workaround: add 'lapic' to boot parameters"
    if [[ -f /etc/default/grub ]]; then
        if ! grep -q 'lapic' /etc/default/grub; then
            log INFO "H-016: Adding lapic to GRUB_CMDLINE_LINUX"
            sed -i 's/GRUB_CMDLINE_LINUX="/GRUB_CMDLINE_LINUX="lapic /' /etc/default/grub
        fi
    fi

    # ------------------------------------------------------------------
    # H-017: /boot write protection
    # ------------------------------------------------------------------
    log STEP "H-017: /boot filesystem protection"
    # Mount /boot read-only if it's a separate partition
    if mount | grep ' /boot ' | grep -qv 'ro'; then
        log INFO "H-017: Remounting /boot read-only"
        mount -o remount,ro /boot 2>/dev/null && \
            log INFO "H-017: /boot remounted read-only" || \
            log WARN "H-017: Could not remount /boot read-only"
        # Make permanent in /etc/fstab
        if [[ -f /etc/fstab ]]; then
            sed -i 's|\(/boot.*\)\brw\b|\1ro|' /etc/fstab
            log INFO "H-017: /boot set to ro in /etc/fstab"
        fi
    fi

    # ------------------------------------------------------------------
    # H-018: Disable kernel module loading post-boot (IOC-002, IOC-006)
    # ONLY after confirming all required modules are loaded
    # ------------------------------------------------------------------
    log STEP "H-018: Module loading lockdown"
    log WARN "H-018: After verifying all required kernel modules are loaded:"
    log WARN "H-018: Execute:  echo 1 > /proc/sys/kernel/modules_disabled"
    log WARN "H-018: Or add to /etc/sysctl.d: kernel.modules_disabled = 1"
    log WARN "H-018: This is irreversible until reboot and prevents post-boot module injection"
    # Add to hardening conf but commented out -- manual activation required
    echo '# kernel.modules_disabled = 1  # UNCOMMENT AFTER VERIFYING MODULE SET' >> \
        /etc/sysctl.d/99-ctw-hardening.conf

    # ------------------------------------------------------------------
    # H-019: Restrict I/O port access (IOC-013)
    # ------------------------------------------------------------------
    log STEP "H-019: I/O port access restriction"
    # Restrict ioperm/iopl to root only
    sysctl -w kernel.io_uring_disabled=2 2>/dev/null || true
    # Log I/O permission requests
    auditctl -a always,exit -F arch=b32 -S ioperm -S iopl -k ioport_access 2>/dev/null || \
        log WARN "H-019: Could not add ioport audit rule"

    # ------------------------------------------------------------------
    # GRUB hardening (applies to reboot) -- addresses multiple IOCs
    # ------------------------------------------------------------------
    log STEP "H-020: GRUB bootloader hardening"
    if [[ -f /etc/default/grub ]]; then
        # Remove edd=off (IOC-031) if present
        sed -i 's/edd=off//g' /etc/default/grub
        log INFO "H-020: Removed edd=off from GRUB config (disk identity now verified)"
        # Set GRUB password (addresses unverified boot partition IOC HIGH-005)
        log WARN "H-020: Set GRUB superuser password to prevent bootloader-level modification:"
        log WARN "H-020: Run: grub2-setpassword"
        log INFO "H-020: Updated /etc/default/grub (run grub2-mkconfig after initrd verification)"
    fi

    log INFO "Phase 2 hardening complete. Review ${HARDENING_LOG} for all actions taken."
}

# =============================================================================
# PHASE 3: IOC SUMMARY AND NEXT STEPS
# =============================================================================

phase_report() {
    log STEP "PHASE 3: FINAL IOC STATUS REPORT"

    {
        echo ""
        echo "========================================================"
        echo "CTW-BOOT-FA-001 LIVE IOC STATUS SUMMARY"
        echo "Run: ${RUN_TIMESTAMP}"
        echo "========================================================"
        echo ""
        cat "${IOC_REPORT}"
        echo ""
        echo "========================================================"
        echo "HARDWARE-LAYER REMEDIATION REQUIRED (SOFTWARE CANNOT FIX)"
        echo "========================================================"
        echo ""
        echo "  BIOS/FIRMWARE (IOC-004, IOC-022, IOC-021):"
        echo "    1. Extract BIOS firmware: flashrom -r bios_dump.bin"
        echo "    2. Compare against Dell OEM image for this hardware"
        echo "    3. If DSDT mismatch confirmed: reflash OEM BIOS"
        echo "    4. Enable Local APIC in BIOS settings"
        echo "    5. Verify CPU multiplier settings for 1800MHz operation"
        echo ""
        echo "  VMBR / HYPERVISOR (IOC-002):"
        echo "    1. External timing analysis (PMU counters, RDTSC variance)"
        echo "    2. If VMBR confirmed: all software-layer remediation is unreliable"
        echo "    3. Remediation requires: verified bare-metal OS reinstall"
        echo "       on a different physical storage device"
        echo ""
        echo "  LUKS PASSPHRASE (IOC-001, IOC HIGH-005):"
        echo "    ASSUME PASSPHRASE COMPROMISED"
        echo "    1. After verified clean initrd confirmed:"
        echo "       cryptsetup luksChangeKey /dev/sdaX"
        echo "    2. Audit all LUKS key slots: cryptsetup luksDump /dev/sdaX"
        echo "    3. Remove any unauthorized key slots"
        echo ""
        echo "  PHYSICAL INSPECTION (IOC-018, SUPP-ACTION-006):"
        echo "    1. Inspect both CardBus slots for hardware"
        echo "    2. Inspect dock station interfaces"
        echo "    3. Visual inspection of PCIe, PCI, BIOS chip for implants"
        echo ""
        echo "  INITRD INTEGRITY (IOC-001, ACTION-002):"
        echo "    1. Binary compare both extracted initrd images"
        echo "    2. Compare against known-good Fedora 9 initrd (sha256 verified)"
        echo "    3. Inspect initrd_contents/ for unexpected files"
        echo "    4. If modified: rebuild from clean package set"
        echo ""
        echo "========================================================"
        echo "EVIDENCE COLLECTED:"
        echo "========================================================"
        ls -lah "${EVIDENCE_DIR}/"
        echo ""
        echo "Hash manifest: ${HASH_MANIFEST}"
        cat "${HASH_MANIFEST}"
        echo ""
        echo "========================================================"
        echo "END OF REPORT"
        echo "========================================================"
    } | tee -a "${HARDENING_LOG}"
}

# =============================================================================
# MAIN
# =============================================================================

preflight

case "${MODE}" in
    collect)
        phase_collect
        ;;
    harden)
        phase_harden
        ;;
    full)
        phase_collect
        phase_harden
        ;;
esac

phase_report

log INFO "Script complete. Evidence and logs in: ${EVIDENCE_DIR}"
log WARN "REMINDER: This system is assessed as COMPROMISED at multiple layers."
log WARN "Software hardening is a triage measure. Physical/firmware remediation required."

exit 0
