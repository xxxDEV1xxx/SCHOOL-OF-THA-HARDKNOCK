#Requires -RunAsAdministrator
<#
================================================================================
  SERIAL DOCUMENTING ARCHITECTURE RESEARCH (SDAR)
  Host Guard Application -- Windows 10 Side
  Inventor : Christopher T. Williams
  Conceived: 20 March 2026 (PST 20:05:00) / 21 March 2026 (UTC 04:05:00)
  Version  : 1.0.1 -- Expert Witness / LegendaryBlueTeam Edition (ASCII)

  AI ASSISTANCE DISCLOSURE (Appendix A):
    Grok (xAI) and Claude (Anthropic) assisted solely in translating the
    inventor's architecture into executable code. All design decisions,
    forensic methodology, pipe topology, EWF evidence strategy, RFC 2217
    emulation approach, dual-guard architecture, and chain-of-custody model
    are the original, sole work of Christopher T. Williams. The AI tools
    performed no architectural reasoning and exercised no creative control
    over the invention's structure or scope.
================================================================================

DESCRIPTION:
  Creates \\.\pipe\KaliSerialGuard as a persistent named pipe SERVER before
  any VM boots -- solving the chicken-and-egg timing problem definitively.

  Implements RFC 2217 COM-PORT-OPTION negotiation, bidirectional mux over
  single ttyS0, interactive terminal + INJECT: override mode, and parallel
  dual EWF .01 acquisition of serial stream + host physical memory.

EVIDENCE PRODUCED:
  [E01-A] Serial.E01    -- every byte transiting ttyS0, memory-direct
  [E01-B] HostRAM.E01   -- Windows host physical memory via WinPmem
  [LOG]   HashChain.log -- tamper-evident SHA-256 chained session log

USAGE:
  powershell -ExecutionPolicy Bypass -File SerialGuard-Host.ps1

  Interactive commands during session:
    INJECT:<command>   -- override mode, push command string to VM
    BREAK              -- inject RFC 2217 break/interrupt signal
    MEMACQ             -- trigger on-demand host memory acquisition
    QUIT               -- graceful shutdown with evidence finalization
#>

# -----------------------------------------------------------------------
# CONFIGURATION
# -----------------------------------------------------------------------
$CFG = @{
    PipeName        = "KaliSerialGuard"
    PipeFullPath    = "\\.\pipe\KaliSerialGuard"
    EvidenceRoot    = "C:\ForensicEvidence\SDAR"
    CaseNumber      = "SDAR-2026-001"
    ExaminerName    = "Christopher T. Williams"
    ExaminerOrg     = "Independent Security Research"
    ExaminerNotes   = "SDAR VM Serial Forensic Capture - RFC 2217 Named Pipe"
    WinPmemPath     = "C:\Tools\Forensic\winpmem_mini_x64_rc2.exe"
    EwfAcquirePath  = "C:\Tools\Forensic\ewfacquire.exe"
    BaudRate        = 115200
    IAC             = [byte]0xFF
    WILL            = [byte]0xFB
    DO              = [byte]0xFD
    SB              = [byte]0xFA
    SE              = [byte]0xF0
    COM_PORT_OPTION = [byte]0x2C
    BREAK_STATE     = [byte]0x0C
}

# -----------------------------------------------------------------------
# SESSION GLOBALS
# -----------------------------------------------------------------------
$script:SessionID  = [Guid]::NewGuid().ToString("N").Substring(0,12).ToUpper()
$script:StartUTC   = [DateTime]::UtcNow
$script:StartPST   = [TimeZoneInfo]::ConvertTimeBySystemTimeZoneId(
                         $script:StartUTC, "Pacific Standard Time")
$script:PrevHash   = ("0" * 64)
$script:ByteIn     = [UInt64]0
$script:ByteOut    = [UInt64]0
$script:LogPath    = $null
$script:RawPath    = $null
$script:RawStream  = $null
$script:Pipe       = $null
$script:Running    = $true
$script:InjQueue   = [System.Collections.Concurrent.ConcurrentQueue[string]]::new()

# -----------------------------------------------------------------------
# INITIALIZE
# Create directory tree, lock ACL, register event source, set file paths
# -----------------------------------------------------------------------
function Initialize-Environment {

    $dirs = @(
        $CFG.EvidenceRoot,
        "$($CFG.EvidenceRoot)\SessionLogs",
        "$($CFG.EvidenceRoot)\EWF-Serial",
        "$($CFG.EvidenceRoot)\EWF-Memory",
        "$($CFG.EvidenceRoot)\RawStreams"
    )
    foreach ($d in $dirs) {
        if (-not (Test-Path $d)) {
            New-Item -ItemType Directory -Path $d -Force | Out-Null
        }
    }

    $acl = Get-Acl $CFG.EvidenceRoot
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($id in @("SYSTEM", "Administrators")) {
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $id, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
        $acl.AddAccessRule($rule)
    }
    Set-Acl -Path $CFG.EvidenceRoot -AclObject $acl

    if (-not [System.Diagnostics.EventLog]::SourceExists("SDAR")) {
        [System.Diagnostics.EventLog]::CreateEventSource("SDAR", "Application")
    }

    $ts               = $script:StartUTC.ToString("yyyyMMdd_HHmmss")
    $script:LogPath   = "$($CFG.EvidenceRoot)\SessionLogs\SDAR_$($script:SessionID)_$ts.log"
    $script:RawPath   = "$($CFG.EvidenceRoot)\RawStreams\SDAR_$($script:SessionID)_$ts.raw"
    $script:RawStream = [System.IO.File]::Open(
        $script:RawPath,
        [System.IO.FileMode]::Create,
        [System.IO.FileAccess]::Write,
        [System.IO.FileShare]::Read)

    Write-Log "INIT" "=== SDAR SESSION $($script:SessionID) START ==="
    Write-Log "INIT" "UTC  : $($script:StartUTC.ToString('yyyy-MM-ddTHH:mm:ss'))Z"
    Write-Log "INIT" "PST  : $($script:StartPST.ToString('yyyy-MM-dd HH:mm:ss')) PST"
    Write-Log "INIT" "Case : $($CFG.CaseNumber)  Examiner : $($CFG.ExaminerName)"
    Write-Log "INIT" "Pipe : $($CFG.PipeFullPath)"
    Write-Log "INIT" "Raw  : $($script:RawPath)"
}

# -----------------------------------------------------------------------
# HASH-CHAINED LOGGING
# Hash = SHA-256( prevHash || timestamp || level || message )
# -----------------------------------------------------------------------
function Write-Log {
    param(
        [string]$Level,
        [string]$Msg,
        [byte[]]$Bytes = $null
    )

    $ts      = [DateTime]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.ffffffZ")
    $hexDump = if ($Bytes) { [BitConverter]::ToString($Bytes).Replace("-","") } else { "" }
    $content = "$ts|$($script:SessionID)|$Level|$Msg|$($script:ByteIn)|$($script:ByteOut)|$hexDump"

    $sha256  = [System.Security.Cryptography.SHA256]::Create()
    $raw     = [System.Text.Encoding]::UTF8.GetBytes($script:PrevHash + $content)
    $hash    = [BitConverter]::ToString($sha256.ComputeHash($raw)).Replace("-","").ToLower()
    $script:PrevHash = $hash

    $line = "$ts | $($script:SessionID) | $Level | CHAIN:$hash | $Msg"
    if ($hexDump) { $line += " | HEX[$($Bytes.Length)]:$hexDump" }

    Add-Content -Path $script:LogPath -Value $line -Encoding UTF8

    try {
        [System.Diagnostics.EventLog]::WriteEntry("SDAR", $line, "Information", 1000)
    } catch {}

    $color = switch ($Level) {
        "INIT"    { "Cyan"    }
        "CONNECT" { "Green"   }
        "VM-OUT"  { "White"   }
        "INJECT"  { "Red"     }
        "BREAK"   { "Magenta" }
        "MEMACQ"  { "Yellow"  }
        "ERROR"   { "DarkRed" }
        default   { "Gray"    }
    }
    Write-Host $line -ForegroundColor $color
}

# -----------------------------------------------------------------------
# NAMED PIPE SERVER
# Pipe exists before VM boots -- eliminates boot race condition
# -----------------------------------------------------------------------
function New-GuardPipe {

    $sec = New-Object System.IO.Pipes.PipeSecurity
    foreach ($id in @("SYSTEM", "Administrators")) {
        $rule = New-Object System.IO.Pipes.PipeAccessRule(
            $id,
            [System.IO.Pipes.PipeAccessRights]::FullControl,
            [System.Security.AccessControl.AccessControlType]::Allow)
        $sec.AddAccessRule($rule)
    }

    $pipe = New-Object System.IO.Pipes.NamedPipeServerStream(
        $CFG.PipeName,
        [System.IO.Pipes.PipeDirection]::InOut,
        1,
        [System.IO.Pipes.PipeTransmissionMode]::Byte,
        [System.IO.Pipes.PipeOptions]::Asynchronous,
        65536,
        65536,
        $sec
    )

    Write-Log "INIT" "Pipe server armed -- waiting for VMware VM connection..."
    return $pipe
}

# -----------------------------------------------------------------------
# RFC 2217 NEGOTIATION
# -----------------------------------------------------------------------
function Send-RFC2217Init {
    param([System.IO.Stream]$S)

    $S.Write([byte[]]@($CFG.IAC, $CFG.WILL, $CFG.COM_PORT_OPTION), 0, 3)

    $b = $CFG.BaudRate
    $baudBytes = [byte[]]@(
        ($b -shr 24) -band 0xFF,
        ($b -shr 16) -band 0xFF,
        ($b -shr  8) -band 0xFF,
        ($b        ) -band 0xFF
    )
    $pkt = [byte[]]@($CFG.IAC,$CFG.SB,$CFG.COM_PORT_OPTION,0x01) `
           + $baudBytes `
           + [byte[]]@($CFG.IAC,$CFG.SE)
    $S.Write($pkt, 0, $pkt.Length)

    $S.Write([byte[]]@($CFG.IAC,$CFG.SB,$CFG.COM_PORT_OPTION,0x02,0x08,$CFG.IAC,$CFG.SE), 0, 7)
    $S.Write([byte[]]@($CFG.IAC,$CFG.SB,$CFG.COM_PORT_OPTION,0x03,0x01,$CFG.IAC,$CFG.SE), 0, 7)
    $S.Write([byte[]]@($CFG.IAC,$CFG.SB,$CFG.COM_PORT_OPTION,0x04,0x01,$CFG.IAC,$CFG.SE), 0, 7)
    $S.Write([byte[]]@($CFG.IAC,$CFG.SB,$CFG.COM_PORT_OPTION,0x05,0x01,$CFG.IAC,$CFG.SE), 0, 7)
    $S.Flush()

    Write-Log "CONNECT" "RFC 2217 negotiation sent: $($CFG.BaudRate)/8N1/NoFlow"
}

# -----------------------------------------------------------------------
# RFC 2217 BREAK INJECTION
# -----------------------------------------------------------------------
function Send-Break {
    param([System.IO.Stream]$S)

    $pkt = [byte[]]@(
        $CFG.IAC, $CFG.SB, $CFG.COM_PORT_OPTION,
        0x05, $CFG.BREAK_STATE,
        $CFG.IAC, $CFG.SE)
    $S.Write($pkt, 0, $pkt.Length)
    $S.Flush()
    Write-Log "BREAK" "RFC 2217 BREAK/INTERRUPT injected to VM"
}

# -----------------------------------------------------------------------
# EWF SERIAL STREAM WRAP
# -----------------------------------------------------------------------
function Invoke-EWFSerialWrap {

    try { $script:RawStream.Flush(); $script:RawStream.Close() } catch {}

    if (-not (Test-Path $script:RawPath)) {
        Write-Log "ERROR" "Raw evidence file missing: $($script:RawPath)"
        return
    }

    $ts     = [DateTime]::UtcNow.ToString("yyyyMMdd_HHmmss")
    $ewfOut = "$($CFG.EvidenceRoot)\EWF-Serial\SDAR_SERIAL_$($script:SessionID)_$ts"

    Write-Log "INIT" "Wrapping serial stream to EWF: $ewfOut.E01"

    $ewfArgs = @(
        "-t", $ewfOut,
        "-C", $CFG.CaseNumber,
        "-e", $CFG.ExaminerName,
        "-D", $CFG.ExaminerNotes,
        "-m", "logical",
        "-c", "deflate",
        "-f", "encase6",
        "-u",
        $script:RawPath
    )

    try {
        $p = Start-Process $CFG.EwfAcquirePath `
             -ArgumentList $ewfArgs -Wait -PassThru -NoNewWindow
        if ($p.ExitCode -eq 0) {
            Write-Log "INIT" "EWF serial evidence finalized: $ewfOut.E01"
        } else {
            Write-Log "ERROR" "ewfacquire exit code: $($p.ExitCode)"
        }
    } catch {
        Write-Log "ERROR" "EWF serial wrap exception: $_"
    }
}

# -----------------------------------------------------------------------
# HOST MEMORY ACQUISITION
# WinPmem raw -> hash -> ewfacquire -> HostRAM.E01
# -----------------------------------------------------------------------
function Invoke-MemoryAcquisition {

    $ts     = [DateTime]::UtcNow.ToString("yyyyMMdd_HHmmss")
    $rawMem = "$($CFG.EvidenceRoot)\EWF-Memory\SDAR_MEM_$($script:SessionID)_$ts.raw"
    $ewfOut = "$($CFG.EvidenceRoot)\EWF-Memory\SDAR_MEM_$($script:SessionID)_$ts"

    Write-Log "MEMACQ" "=== HOST MEMORY ACQUISITION INITIATED ==="
    Write-Log "MEMACQ" "WinPmem target: $rawMem"

    try {
        $p = Start-Process $CFG.WinPmemPath `
             -ArgumentList @($rawMem) -Wait -PassThru -NoNewWindow
        Write-Log "MEMACQ" "WinPmem exit code: $($p.ExitCode)"
    } catch {
        Write-Log "ERROR" "WinPmem failed: $_"
        return
    }

    $md5 = (Get-FileHash $rawMem -Algorithm MD5).Hash
    $sha = (Get-FileHash $rawMem -Algorithm SHA256).Hash
    Write-Log "MEMACQ" "Raw MD5    : $md5"
    Write-Log "MEMACQ" "Raw SHA256 : $sha"

    $ewfArgs = @(
        "-t", $ewfOut,
        "-C", $CFG.CaseNumber,
        "-e", $CFG.ExaminerName,
        "-D", "Win10 Host Physical Memory -- SDAR Session $($script:SessionID)",
        "-m", "memory",
        "-c", "deflate",
        "-f", "encase6",
        "-u",
        $rawMem
    )
    try {
        $p = Start-Process $CFG.EwfAcquirePath `
             -ArgumentList $ewfArgs -Wait -PassThru -NoNewWindow
        if ($p.ExitCode -eq 0) {
            Write-Log "MEMACQ" "HostRAM EWF finalized    : $ewfOut.E01"
            Write-Log "MEMACQ" "Volatility 3 ready target: $ewfOut.E01"
        } else {
            Write-Log "ERROR" "EWF memory wrap exit: $($p.ExitCode)"
        }
    } catch {
        Write-Log "ERROR" "EWF memory wrap exception: $_"
    }

    Write-Log "MEMACQ" "=== MEMORY ACQUISITION COMPLETE ==="
}

# -----------------------------------------------------------------------
# BACKGROUND INPUT LISTENER
# -----------------------------------------------------------------------
function Start-InputListener {
    $queue = $script:InjQueue
    $thr = [System.Threading.Thread]::new({
        while ($true) {
            try {
                $line = [Console]::ReadLine()
                if ($null -ne $line) { $queue.Enqueue($line) }
            } catch { break }
        }
    })
    $thr.IsBackground = $true
    $thr.Start()
}

# -----------------------------------------------------------------------
# MAIN GUARD LOOP
# -----------------------------------------------------------------------
function Start-GuardSession {

    $buf = New-Object byte[] 4096

    while ($script:Running) {
        try {

            # VM -> Host: read bytes, log, write to raw evidence file
            if ($script:Pipe.IsConnected -and $script:Pipe.CanRead) {
                $n = 0
                try { $n = $script:Pipe.Read($buf, 0, $buf.Length) } catch {}
                if ($n -gt 0) {
                    $data = $buf[0..($n - 1)]
                    $script:ByteIn += $n
                    $script:RawStream.Write($data, 0, $n)
                    $script:RawStream.Flush()
                    $text = [System.Text.Encoding]::UTF8.GetString($data)
                    Write-Log "VM-OUT" $text.Trim() $data
                }
            }

            # Host -> VM: operator input dispatch
            $cmd = ""
            if ($script:InjQueue.TryDequeue([ref]$cmd)) {

                switch -Regex ($cmd.Trim()) {

                    "^QUIT$" {
                        Write-Log "INIT" "Operator initiated graceful shutdown"
                        $script:Running = $false
                    }

                    "^BREAK$" {
                        Send-Break $script:Pipe
                    }

                    "^MEMACQ$" {
                        Invoke-MemoryAcquisition
                    }

                    "^INJECT:(.+)$" {
                        $payload = $Matches[1]
                        $bytes   = [System.Text.Encoding]::UTF8.GetBytes($payload + "`n")
                        $script:Pipe.Write($bytes, 0, $bytes.Length)
                        $script:Pipe.Flush()
                        $script:ByteOut += $bytes.Length
                        Write-Log "INJECT" "OVERRIDE -> VM: $payload" $bytes
                    }

                    default {
                        $bytes = [System.Text.Encoding]::UTF8.GetBytes($cmd + "`n")
                        $script:Pipe.Write($bytes, 0, $bytes.Length)
                        $script:Pipe.Flush()
                        $script:ByteOut += $bytes.Length
                        Write-Log "INJECT" "Interactive -> VM: $cmd"
                    }
                }
            }

            Start-Sleep -Milliseconds 10

        } catch {
            Write-Log "ERROR" "Guard loop exception: $_"
            Start-Sleep -Seconds 1
        }
    }
}

# -----------------------------------------------------------------------
# ENTRY POINT
# -----------------------------------------------------------------------
try {
    Clear-Host
    Write-Host "+--------------------------------------------------------------+" -ForegroundColor Cyan
    Write-Host "|  SERIAL DOCUMENTING ARCHITECTURE RESEARCH (SDAR)            |" -ForegroundColor Cyan
    Write-Host "|  Inventor : Christopher T. Williams                         |" -ForegroundColor Cyan
    Write-Host "|  LegendaryBlueTeam -- Expert Witness Edition                |" -ForegroundColor Cyan
    Write-Host "|  UTC: $($script:StartUTC.ToString('yyyy-MM-ddTHH:mm:ss'))Z                             |" -ForegroundColor Cyan
    Write-Host "|  PST: $($script:StartPST.ToString('yyyy-MM-dd HH:mm:ss')) PST                         |" -ForegroundColor Cyan
    Write-Host "+--------------------------------------------------------------+" -ForegroundColor Cyan
    Write-Host "  Commands: INJECT:<cmd>  BREAK  MEMACQ  QUIT" -ForegroundColor Yellow
    Write-Host ""

    Initialize-Environment

    $script:Pipe = New-GuardPipe
    Write-Log "INIT" "Pipe armed. Power on VM now. Waiting for VMware connection..."

    $script:Pipe.WaitForConnection()
    Write-Log "CONNECT" "VMware VM connected on $($CFG.PipeFullPath)"

    Send-RFC2217Init $script:Pipe
    Start-InputListener
    Invoke-MemoryAcquisition
    Start-GuardSession

} finally {
    Write-Log "INIT" "=== SDAR SESSION $($script:SessionID) FINALIZING ==="
    Write-Log "INIT" "Bytes IN  (VM->Host) : $($script:ByteIn)"
    Write-Log "INIT" "Bytes OUT (Host->VM) : $($script:ByteOut)"
    Write-Log "INIT" "Chain tail hash      : $($script:PrevHash)"
    Invoke-EWFSerialWrap
    if ($script:Pipe) { try { $script:Pipe.Close() } catch {} }
    Write-Log "INIT" "=== SESSION CLOSED -- EVIDENCE FINALIZED ==="
}
