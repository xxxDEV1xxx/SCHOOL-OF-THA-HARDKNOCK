#!/bin/sh
# =============================================================================
# CTW-DSL-MAXDUMP.SH
# Maximum forensic extraction from DSL 2.4.26 toram session
# Prioritized: most irreplaceable evidence first
# Everything goes to /ramdisk -- transfer before reboot or it is gone
#
# Run: sh ctw_dsl_maxdump.sh 2>&1 | tee /ramdisk/maxdump_console.txt
#
# TRANSFER OPTIONS (pick one before rebooting):
#   netcat:  tar czf - /ramdisk/CTW-MAXDUMP | nc <ip> 9999
#   receive: nc -l -p 9999 > evidence.tar.gz
#
#   If no network: mount USB and cp -r /ramdisk/CTW-MAXDUMP /mnt/usb/
# =============================================================================

DUMP="/ramdisk/CTW-MAXDUMP-$(date +%Y%m%dT%H%M%S)"
mkdir -p "${DUMP}"
START=$(date +%s)

p() { echo ""; echo ">>> $*"; echo ""; }
cap() {
    TAG="$1"; shift
    OUT="${DUMP}/${TAG}.txt"
    { echo "# ${TAG}  $(date)"; echo "# cmd: $*"; echo ""; "$@" 2>&1; } > "${OUT}"
    echo "[+] ${TAG}"
}
capb() {
    # binary capture
    TAG="$1"; shift
    OUT="${DUMP}/${TAG}.bin"
    "$@" > "${OUT}" 2>/dev/null && echo "[+] ${TAG}.bin ($(wc -c < ${OUT}) bytes)" \
        || echo "[!] ${TAG}.bin FAILED"
}

echo "============================================================"
echo "CTW-DSL MAXIMUM FORENSIC DUMP"
echo "Host:   $(uname -n)  Kernel: $(uname -r)"
echo "Time:   $(date)"
echo "Output: ${DUMP}"
echo "============================================================"


# ============================================================
# TIER 1 — BIOS / FIRMWARE LAYER
# Most irreplaceable. Lives in ROM. Survives all OS reinstalls.
# This is what persists after your clean install if not reflashed.
# ============================================================
p "TIER 1: BIOS / FIRMWARE"

# ACPI tables -- binary capture (most valuable)
for TBL in DSDT FADT RSDT SSDT APIC BOOT TCPA; do
    SRC="/proc/acpi/${TBL}"
    [ -f "${SRC}" ] && capb "acpi_${TBL}" cat "${SRC}"
done

# DSDT as strings (human readable, cross-reference INT430 SYSFe)
cap "acpi_dsdt_strings"      strings /proc/acpi/dsdt
cap "acpi_dsdt_hex"          od -A x -t x1z /proc/acpi/dsdt 2>/dev/null | head -200

# Full ACPI proc tree
cap "acpi_tree_full"         ls -laR /proc/acpi/

# CPU0 full ACPI state
cap "acpi_cpu0_info"         cat /proc/acpi/processor/CPU0/info
cap "acpi_cpu0_power"        cat /proc/acpi/processor/CPU0/power
cap "acpi_cpu0_throttle"     cat /proc/acpi/processor/CPU0/throttling
cap "acpi_cpu0_limit"        cat /proc/acpi/processor/CPU0/limit
cap "acpi_cpu0_perf"         cat /proc/acpi/processor/CPU0/performance 2>/dev/null || true

# DMI / SMBIOS -- board, BIOS version, serial, service tag
cap "dmi_bios_version"       cat /proc/acpi/dsdt 2>/dev/null | strings | grep -iE 'bios|version|dell|rev' | head -20
for DMI in bios_version bios_date bios_vendor board_name board_vendor \
           product_name product_serial sys_vendor chassis_type; do
    [ -f "/sys/class/dmi/id/${DMI}" ] && \
        echo "${DMI}: $(cat /sys/class/dmi/id/${DMI} 2>/dev/null)" >> "${DUMP}/dmi_full.txt"
done
# 2.4.26 sysfs likely empty -- try alternate paths
cap "dmi_proc"               cat /proc/acpi/dsdt 2>/dev/null | strings | head -80

# BIOS memory region 0xF0000-0xFFFFF (BIOS ROM shadow in RAM)
# This is where BIOS code lives -- 64KB
p "Imaging BIOS ROM shadow (0xF0000, 64KB)..."
{
    dd if=/dev/mem bs=1024 skip=960 count=64 2>/dev/null | \
        od -A x -t x1z > "${DUMP}/bios_rom_shadow_hex.txt" && \
        echo "[+] BIOS ROM shadow hex dump complete" || \
        echo "[!] /dev/mem read at 0xF0000 failed"
    dd if=/dev/mem bs=1024 skip=960 count=64 \
        of="${DUMP}/bios_rom_shadow.bin" 2>/dev/null && \
        echo "[+] BIOS ROM shadow binary: $(wc -c < ${DUMP}/bios_rom_shadow.bin) bytes" || \
        echo "[!] BIOS ROM binary capture failed"
} 2>&1 | tee -a "${DUMP}/bios_rom_capture.txt"

# BIOS extension ROMs (0xC0000-0xEFFFF) -- option ROMs, VGA BIOS, CardBus ROM
p "Imaging option ROM space (0xC0000-0xEFFFF, 192KB)..."
dd if=/dev/mem bs=1024 skip=768 count=192 \
    of="${DUMP}/option_rom_space.bin" 2>/dev/null && \
    echo "[+] Option ROM space: $(wc -c < ${DUMP}/option_rom_space.bin) bytes" || \
    echo "[!] Option ROM space capture failed"
strings "${DUMP}/option_rom_space.bin" 2>/dev/null > "${DUMP}/option_rom_strings.txt"

# Real mode interrupt vector table (0x00000-0x003FF) -- 1KB, 256 vectors
# APM probe reads from here (IOC LOW-002) -- check for modifications
p "Imaging interrupt vector table (0x0-0x3FF)..."
dd if=/dev/mem bs=1 count=1024 \
    of="${DUMP}/ivt.bin" 2>/dev/null && \
    od -A x -t x2z "${DUMP}/ivt.bin" > "${DUMP}/ivt_hex.txt" && \
    echo "[+] IVT captured ($(wc -c < ${DUMP}/ivt.bin) bytes)" || \
    echo "[!] IVT capture failed"

# BIOS data area (0x00400-0x004FF)
dd if=/dev/mem bs=1 skip=1024 count=256 \
    of="${DUMP}/bda.bin" 2>/dev/null && \
    od -A x -t x1z "${DUMP}/bda.bin" > "${DUMP}/bda_hex.txt" && \
    echo "[+] BIOS data area captured" || \
    echo "[!] BDA capture failed"


# ============================================================
# TIER 2 — PHYSICAL MEMORY REGIONS OF INTEREST
# Specific addresses from forensic report IOCs
# ============================================================
p "TIER 2: TARGETED MEMORY REGIONS"

# IOC-015: Reserved region at top of RAM (0x27fe2800-0x28000000, 7680 bytes)
p "IOC-015: Reserved region 0x27fe2800 (7680 bytes)..."
dd if=/dev/mem bs=1 skip=$((16#27fe2800)) count=7680 \
    of="${DUMP}/ioc015_reserved_0x27fe2800.bin" 2>/dev/null && \
    strings "${DUMP}/ioc015_reserved_0x27fe2800.bin" > "${DUMP}/ioc015_strings.txt" && \
    od -A x -t x1z "${DUMP}/ioc015_reserved_0x27fe2800.bin" > "${DUMP}/ioc015_hex.txt" && \
    echo "[+] IOC-015 region captured ($(wc -c < ${DUMP}/ioc015_reserved_0x27fe2800.bin) bytes)" || \
    echo "[!] IOC-015 region capture failed"

# initrd region 1 -- substituted initrd (IOC-001 lower address)
p "IOC-001: initrd region 0x27c5c000 (0x376144 bytes = 3.5MB)..."
dd if=/dev/mem bs=4096 skip=$((16#27c5c000 / 4096)) count=$((16#376144 / 4096 + 1)) \
    of="${DUMP}/ioc001_initrd_0x27c5c000.bin" 2>/dev/null && \
    echo "[+] initrd region 1 captured: $(wc -c < ${DUMP}/ioc001_initrd_0x27c5c000.bin) bytes" && \
    strings "${DUMP}/ioc001_initrd_0x27c5c000.bin" | head -100 > "${DUMP}/ioc001_initrd1_strings.txt" || \
    echo "[!] initrd region 1 capture failed (addresses may not be populated in 2.4.26)"

# initrd region 2 -- original initrd (higher address)
p "IOC-001: initrd region 0x27c5c800 (0x376144 bytes)..."
dd if=/dev/mem bs=4096 skip=$((16#27c5c800 / 4096)) count=$((16#376144 / 4096 + 1)) \
    of="${DUMP}/ioc001_initrd_0x27c5c800.bin" 2>/dev/null && \
    echo "[+] initrd region 2 captured: $(wc -c < ${DUMP}/ioc001_initrd_0x27c5c800.bin) bytes" && \
    strings "${DUMP}/ioc001_initrd_0x27c5c800.bin" | head -100 > "${DUMP}/ioc001_initrd2_strings.txt" || \
    echo "[!] initrd region 2 capture failed"

# Compare the two initrd regions if both captured
if [ -f "${DUMP}/ioc001_initrd_0x27c5c000.bin" ] && \
   [ -f "${DUMP}/ioc001_initrd_0x27c5c800.bin" ]; then
    md5sum "${DUMP}/ioc001_initrd_0x27c5c000.bin" \
           "${DUMP}/ioc001_initrd_0x27c5c800.bin" > "${DUMP}/ioc001_initrd_compare.txt"
    if diff "${DUMP}/ioc001_initrd_0x27c5c000.bin" \
            "${DUMP}/ioc001_initrd_0x27c5c800.bin" >/dev/null 2>&1; then
        echo "IOC-001: initrd regions IDENTICAL" >> "${DUMP}/ioc001_initrd_compare.txt"
    else
        echo "IOC-001: initrd regions DIFFER -- SUBSTITUTION CONFIRMED" \
            >> "${DUMP}/ioc001_initrd_compare.txt"
    fi
    cat "${DUMP}/ioc001_initrd_compare.txt"
fi

# SMM / SMRAM region hint -- typically 0xA0000-0xBFFFF (VGA) and top of RAM
# SMM code executes below ring-0 -- if anything is here it is invisible to OS
p "VGA/SMM region 0xA0000-0xBFFFF (128KB)..."
dd if=/dev/mem bs=1024 skip=640 count=128 \
    of="${DUMP}/vga_smm_region.bin" 2>/dev/null && \
    strings "${DUMP}/vga_smm_region.bin" > "${DUMP}/vga_smm_strings.txt" && \
    echo "[+] VGA/SMM region captured" || \
    echo "[!] VGA/SMM region capture failed"


# ============================================================
# TIER 3 — HARDWARE IDENTIFICATION
# Survives reboot as physical characteristics
# But capture now while DSL has clean eyes on it
# ============================================================
p "TIER 3: HARDWARE IDENTIFICATION"

# Full PCI enumeration
cap "pci_full_verbose"       lspci -v 2>/dev/null || cat /proc/bus/pci/devices
cap "pci_raw"                cat /proc/bus/pci/devices
cap "pci_proc"               cat /proc/pci 2>/dev/null || true

# IDE disk identity -- full hdparm output
cap "disk_hdparm_I"          hdparm -I /dev/hda 2>/dev/null || hdparm -I /dev/sda 2>/dev/null
cap "disk_hdparm_i"          hdparm -i /dev/hda 2>/dev/null || hdparm -i /dev/sda 2>/dev/null
cap "disk_proc_ide"          cat /proc/ide/hda/model 2>/dev/null || true
cap "disk_proc_ide_driver"   cat /proc/ide/hda/driver 2>/dev/null || true
cap "disk_proc_ide_capacity" cat /proc/ide/hda/capacity 2>/dev/null || true
cap "disk_partitions"        cat /proc/partitions
cap "disk_fdisk"             fdisk -l 2>/dev/null || true

# CPU full identification
cap "cpu_cpuinfo"            cat /proc/cpuinfo
cap "cpu_mtrr"               cat /proc/mtrr

# Memory map -- full e820 as seen by 2.4.26
cap "mem_iomem"              cat /proc/iomem
cap "mem_meminfo"            cat /proc/meminfo
cap "mem_dma"                cat /proc/dma

# USB
cap "usb_devices"            cat /proc/bus/usb/devices 2>/dev/null || true
cap "usb_lsusb"              lsusb 2>/dev/null || true

# Input devices
cap "input_devices"          cat /proc/bus/input/devices

# CardBus / PCMCIA
cap "cardbus_lspci"          lspci -v 2>/dev/null | grep -A 10 -i 'cardbus\|yenta' || true


# ============================================================
# TIER 4 — KERNEL / DRIVER LAYER
# The unknown vc driver, symbol table, module state
# ============================================================
p "TIER 4: KERNEL AND DRIVER STATE"

# TTY driver table -- the unknown vc/%d entry
cap "tty_drivers_full"       cat /proc/tty/drivers
cap "tty_driver_serial"      cat /proc/tty/driver/serial 2>/dev/null || true
cap "tty_ldisc"              ls -la /proc/tty/ldisc/ 2>/dev/null && \
                             cat /proc/tty/ldisc/* 2>/dev/null || true
cap "tty_ldiscs"             cat /proc/tty/ldiscs 2>/dev/null || true

# Kernel symbol table -- full dump (most valuable for unknown driver)
cap "ksyms_full"             cat /proc/ksyms 2>/dev/null
cap "ksyms_console_vt"       grep -iE 'con_|vt_|vc_|console|keyboard|kbd' \
                             /proc/ksyms 2>/dev/null || true

# All loaded modules
cap "modules_full"           cat /proc/modules
cap "modules_proc_driver"    ls -laR /proc/tty/driver/ 2>/dev/null || true

# Interrupt table -- IRQ 1 keyboard handler
cap "interrupts_full"        cat /proc/interrupts

# I/O ports -- IOC-013 gap at 0xf300
cap "ioports_full"           cat /proc/ioports

# Kernel taint flag
cap "kernel_tainted"         cat /proc/sys/kernel/tainted
cap "kernel_version"         cat /proc/version
cap "kernel_osrelease"       cat /proc/sys/kernel/osrelease

# Full dmesg -- boot messages from clean 2.4.26 perspective
cap "dmesg_full"             dmesg

# /proc/ksyms sorted by address -- helps identify foreign code regions
{
    echo "# ksyms sorted by address"
    awk '{print $1, $2, $3}' /proc/ksyms 2>/dev/null | sort
} > "${DUMP}/ksyms_sorted.txt"
echo "[+] ksyms_sorted"

# Address range analysis -- flag anything outside expected kernel .text
{
    echo "# Kernel address range analysis"
    echo "# Expected kernel .text: 0xc0100000 - 0xc0800000 (approx)"
    echo "# Module addresses: below 0xc0000000 or above 0xc0ffffff is suspicious"
    echo ""
    awk '{
        addr = strtonum("0x" $1)
        if (addr < 0xc0100000 || addr > 0xc0ffffff)
            print "OUT-OF-RANGE:", $1, $2, $3
    }' /proc/ksyms 2>/dev/null | head -50 || \
    echo "[awk strtonum not available in this busybox build]"
} > "${DUMP}/ksyms_address_analysis.txt"
echo "[+] ksyms_address_analysis"


# ============================================================
# TIER 5 — BOOT PARTITION (read-only)
# GRUB config, kernel images, initrd on the actual /dev/hda
# ============================================================
p "TIER 5: BOOT PARTITION READ"

# Mount /dev/hda1 read-only (likely the boot/root partition)
mkdir -p /mnt/hda1 /mnt/hda2 /mnt/hda3

for PART in hda1 hda2 hda3 hda4; do
    DEV="/dev/${PART}"
    if [ -b "${DEV}" ]; then
        MNT="/mnt/${PART}"
        mkdir -p "${MNT}"
        # Try ext2/ext3 read-only first
        mount -o ro "${DEV}" "${MNT}" 2>/dev/null && {
            echo "[+] Mounted ${DEV} at ${MNT}"

            # Full directory listing
            ls -laR "${MNT}" > "${DUMP}/fs_${PART}_ls.txt" 2>/dev/null
            echo "[+] fs_${PART}_ls"

            # GRUB config
            for GRUBCFG in "${MNT}/boot/grub/menu.lst" \
                           "${MNT}/grub/menu.lst" \
                           "${MNT}/boot/grub/grub.conf"; do
                [ -f "${GRUBCFG}" ] && {
                    cp "${GRUBCFG}" "${DUMP}/grub_$(basename ${GRUBCFG})_${PART}.txt"
                    echo "[+] GRUB config from ${GRUBCFG}"
                    cat "${DUMP}/grub_$(basename ${GRUBCFG})_${PART}.txt"
                }
            done

            # System.map files -- symbol addresses for installed kernels
            for SMAP in "${MNT}/boot/System.map"*; do
                [ -f "${SMAP}" ] && {
                    cp "${SMAP}" "${DUMP}/$(basename ${SMAP})_${PART}.txt"
                    echo "[+] $(basename ${SMAP}) from ${PART}"
                }
            done

            # Kernel images -- hash them
            for KIMG in "${MNT}/boot/vmlinuz"* "${MNT}/boot/bzImage"* \
                        "${MNT}/boot/kernel"*; do
                [ -f "${KIMG}" ] && {
                    md5sum "${KIMG}" >> "${DUMP}/kernel_image_hashes.txt"
                    echo "[+] Hashed $(basename ${KIMG})"
                }
            done

            # initrd files -- hash and extract strings
            for INIRF in "${MNT}/boot/initrd"* "${MNT}/boot/initramfs"*; do
                [ -f "${INIRF}" ] && {
                    md5sum "${INIRF}" >> "${DUMP}/initrd_hashes.txt"
                    strings "${INIRF}" | head -200 \
                        > "${DUMP}/initrd_strings_$(basename ${INIRF})_${PART}.txt"
                    echo "[+] initrd strings: $(basename ${INIRF})"
                }
            done

            # /etc/fstab, /etc/issue, /etc/passwd (no shadow)
            for CF in "${MNT}/etc/fstab" "${MNT}/etc/issue" \
                      "${MNT}/etc/passwd" "${MNT}/etc/modprobe.conf" \
                      "${MNT}/etc/modules.conf" "${MNT}/etc/inittab" \
                      "${MNT}/etc/rc.local" "${MNT}/etc/rc.d/rc.local"; do
                [ -f "${CF}" ] && {
                    cp "${CF}" "${DUMP}/etc_$(echo ${CF} | tr '/' '_')_${PART}.txt"
                    echo "[+] $(basename ${CF}) from ${PART}"
                }
            done

            # /sbin/init -- hash it (modified init = persistent compromise)
            [ -f "${MNT}/sbin/init" ] && \
                md5sum "${MNT}/sbin/init" >> "${DUMP}/critical_binary_hashes.txt"

            # Check for hidden directories (dot-prefixed in unusual locations)
            find "${MNT}" -maxdepth 4 -name '.*' -not -name '..' \
                2>/dev/null >> "${DUMP}/hidden_dirs_${PART}.txt"
            echo "[+] hidden dir scan ${PART}"

            umount "${MNT}" 2>/dev/null
            echo "[+] Unmounted ${DEV}"
        } || echo "[!] Could not mount ${DEV} (wrong fs, encrypted, or empty)"
    fi
done


# ============================================================
# TIER 6 — NETWORK AND PROCESS STATE
# Snapshot of runtime state
# ============================================================
p "TIER 6: RUNTIME STATE"

cap "proc_net_tcp"           cat /proc/net/tcp
cap "proc_net_udp"           cat /proc/net/udp
cap "proc_net_unix"          cat /proc/net/unix
cap "proc_net_dev"           cat /proc/net/dev
cap "proc_net_arp"           cat /proc/net/arp
cap "proc_net_route"         cat /proc/net/route
cap "proc_net_if_inet6"      cat /proc/net/if_inet6 2>/dev/null || true
cap "net_ifconfig"           ifconfig -a
cap "net_wireless"           cat /proc/net/wireless 2>/dev/null || true

cap "ps_full"                ps aux 2>/dev/null || ps -ef
cap "proc_mounts"            cat /proc/mounts
cap "proc_filesystems"       cat /proc/filesystems
cap "proc_devices"           cat /proc/devices
cap "proc_crypto"            cat /proc/crypto 2>/dev/null || \
                             echo "[/proc/crypto not in 2.4.26]"

# Open file descriptors for every process
{
    echo "# All process open file descriptors"
    for pid in $(ls /proc | grep '^[0-9]'); do
        CMD=$(cat /proc/${pid}/cmdline 2>/dev/null | tr '\0' ' ' | cut -c1-50)
        FDS=$(ls -la /proc/${pid}/fd 2>/dev/null)
        if [ -n "${FDS}" ]; then
            echo "=== PID ${pid}: ${CMD} ==="
            echo "${FDS}"
            echo ""
        fi
    done
} > "${DUMP}/all_proc_fds.txt"
echo "[+] all_proc_fds"

# Maps for each process (memory layout)
{
    echo "# Process memory maps"
    for pid in $(ls /proc | grep '^[0-9]'); do
        CMD=$(cat /proc/${pid}/cmdline 2>/dev/null | tr '\0' ' ' | cut -c1-50)
        MAPS=$(cat /proc/${pid}/maps 2>/dev/null)
        if [ -n "${MAPS}" ]; then
            echo "=== PID ${pid}: ${CMD} ==="
            echo "${MAPS}"
            echo ""
        fi
    done
} > "${DUMP}/all_proc_maps.txt"
echo "[+] all_proc_maps"


# ============================================================
# TIER 7 — FULL /proc TREE TEXT CAPTURE
# Everything readable as text
# ============================================================
p "TIER 7: FULL /proc TEXT CAPTURE"

for F in /proc/cmdline /proc/cpuinfo /proc/meminfo /proc/modules \
         /proc/ioports /proc/iomem /proc/interrupts /proc/partitions \
         /proc/mtrr /proc/dma /proc/locks /proc/loadavg /proc/uptime \
         /proc/version /proc/stat /proc/swaps /proc/slabinfo \
         /proc/execdomains /proc/filesystems; do
    [ -f "${F}" ] && {
        cp "${F}" "${DUMP}/proc_$(basename ${F}).txt" 2>/dev/null
        echo "[+] proc_$(basename ${F})"
    }
done

# /proc/scsi
cap "proc_scsi"              cat /proc/scsi/scsi 2>/dev/null || true
cap "proc_ide_full"          ls -laR /proc/ide/ 2>/dev/null || true

# /proc/sys full readable tree
{
    find /proc/sys -type f 2>/dev/null | while read F; do
        echo "=== ${F} ==="
        cat "${F}" 2>/dev/null || echo "[unreadable]"
    done
} > "${DUMP}/proc_sys_full.txt"
echo "[+] proc_sys_full"


# ============================================================
# MANIFEST AND TRANSFER INSTRUCTIONS
# ============================================================
p "GENERATING MANIFEST"

MANIFEST="${DUMP}/MANIFEST.txt"
{
    echo "CTW-DSL-MAXDUMP MANIFEST"
    echo "Session: $(date)"
    echo "Kernel:  $(uname -r)"
    echo "Host:    $(uname -n)"
    echo ""
    echo "FILE HASHES (MD5):"
    find "${DUMP}" -type f ! -name "MANIFEST.txt" | sort | while read F; do
        md5sum "${F}" 2>/dev/null || echo "HASH_FAILED ${F}"
    done
    echo ""
    echo "TOTAL SIZE:"
    du -sh "${DUMP}" 2>/dev/null
    echo ""
    echo "FILE COUNT:"
    find "${DUMP}" -type f | wc -l
} > "${MANIFEST}"
cat "${MANIFEST}"

END=$(date +%s)
ELAPSED=$((END - START))

echo ""
echo "============================================================"
echo "DUMP COMPLETE in ${ELAPSED} seconds"
echo "Output: ${DUMP}"
echo "Size:   $(du -sh ${DUMP} 2>/dev/null | awk '{print $1}')"
echo "Files:  $(find ${DUMP} -type f | wc -l)"
echo ""
echo "TRANSFER BEFORE REBOOT:"
echo ""
echo "  Option A -- netcat (fastest):"
echo "    THIS machine:    tar czf - ${DUMP} | nc <receive-ip> 9999"
echo "    RECEIVE machine: nc -l -p 9999 > ctw_maxdump.tar.gz"
echo ""
echo "  Option B -- USB drive:"
echo "    mkdir /mnt/usb"
echo "    mount /dev/sda1 /mnt/usb  (adjust device)"
echo "    cp -r ${DUMP} /mnt/usb/"
echo "    umount /mnt/usb"
echo ""
echo "  Option C -- write key files to CD-RW if drive supports it:"
echo "    cdrecord dev=/dev/hdc -data ${DUMP}/MANIFEST.txt"
echo ""
echo "DO NOT REBOOT UNTIL TRANSFER IS CONFIRMED ON RECEIVE END"
echo "============================================================"
