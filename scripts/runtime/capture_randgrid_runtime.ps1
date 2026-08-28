[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $OutputDirectory,

    [Parameter(Mandatory = $true)]
    [string] $PythonPath,

    [ValidateRange(10, 300)]
    [int] $DurationSeconds = 10,

    [ValidateRange(0.1, 10.0)]
    [double] $HandleIntervalSeconds = 0.5,

    [int] $TargetPid = 0
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal] $identity
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Write-CaptureStatus {
    param(
        [Parameter(Mandatory = $true)] [string] $Phase,
        [string] $Message = '',
        [hashtable] $Extra = @{}
    )

    $payload = [ordered]@{
        schema_version = 1
        phase = $Phase
        message = $Message
        updated_utc = [DateTimeOffset]::UtcNow.ToString('o')
        session_names = @(
            $script:AuditSessionName,
            $script:ProcessSessionName,
            $script:ObSessionName
        )
        target_pid = $script:ResolvedTargetPid
    }
    foreach ($entry in $Extra.GetEnumerator()) {
        $payload[$entry.Key] = $entry.Value
    }
    $payload | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $script:StatusPath -Encoding utf8
}

function Resolve-DriverPath {
    param([string] $PathName)

    if ($PathName.StartsWith('\??\')) {
        return $PathName.Substring(4)
    }
    return $PathName
}

$resolvedOutput = [System.IO.Path]::GetFullPath($OutputDirectory)
New-Item -ItemType Directory -Force -Path $resolvedOutput | Out-Null

$script:SessionName = 'RandgridAudit-' + $PID + '-' + [DateTimeOffset]::UtcNow.ToString('yyyyMMddHHmmss')
$script:AuditSessionName = $script:SessionName + '-Audit'
$script:ProcessSessionName = $script:SessionName + '-Process'
$script:ObSessionName = $script:SessionName + '-ObHandle'
$script:ResolvedTargetPid = $TargetPid
$script:StatusPath = Join-Path $resolvedOutput 'capture-status.json'
$auditEtlPath = Join-Path $resolvedOutput 'kernel-audit.etl'
$auditDumpPath = Join-Path $resolvedOutput 'kernel-audit-dump.txt'
$auditCsvPath = Join-Path $resolvedOutput 'kernel-audit.csv'
$auditSummaryPath = Join-Path $resolvedOutput 'kernel-audit-summary.txt'
$processEtlPath = Join-Path $resolvedOutput 'kernel-process.etl'
$processDumpPath = Join-Path $resolvedOutput 'kernel-process-dump.txt'
$processCsvPath = Join-Path $resolvedOutput 'kernel-process.csv'
$processSummaryPath = Join-Path $resolvedOutput 'kernel-process-summary.txt'
$obEtlPath = Join-Path $resolvedOutput 'kernel-ob-handle.etl'
$obDumpPath = Join-Path $resolvedOutput 'kernel-ob-handle-dump.txt'
$obCsvPath = Join-Path $resolvedOutput 'kernel-ob-handle.csv'
$obSummaryPath = Join-Path $resolvedOutput 'kernel-ob-handle-summary.txt'
$handlesPath = Join-Path $resolvedOutput 'process-handles.jsonl'
$preflightPath = Join-Path $resolvedOutput 'runtime-preflight.json'
$xperfPath = 'C:\Program Files (x86)\Windows Kits\10\Windows Performance Toolkit\xperf.exe'
$tracelogPath = 'C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\tracelog.exe'
$handleScript = Join-Path $PSScriptRoot 'snapshot_process_handles.py'
$auditSessionStarted = $false
$processSessionStarted = $false
$obSessionStarted = $false
$snapshotProcess = $null

Write-CaptureStatus -Phase 'preflight' -Message 'Validating elevation, target, driver, and tracing tools.'

try {
    if (-not (Test-IsAdministrator)) {
        throw 'Administrator elevation is required for Microsoft-Windows-Kernel-* ETW providers.'
    }
    if (-not (Test-Path -LiteralPath $xperfPath -PathType Leaf)) {
        throw "xperf.exe is unavailable at $xperfPath"
    }
    if (-not (Test-Path -LiteralPath $tracelogPath -PathType Leaf)) {
        throw "tracelog.exe is unavailable at $tracelogPath"
    }
    if (-not (Test-Path -LiteralPath $PythonPath -PathType Leaf)) {
        throw "Python is unavailable at $PythonPath"
    }
    if (-not (Test-Path -LiteralPath $handleScript -PathType Leaf)) {
        throw "Handle snapshot helper is unavailable at $handleScript"
    }
    foreach ($tool in 'logman.exe', 'tracerpt.exe') {
        if (-not (Get-Command $tool -ErrorAction SilentlyContinue)) {
            throw "$tool is unavailable on PATH."
        }
    }

    $target = if ($TargetPid -gt 0) {
        Get-CimInstance Win32_Process -Filter "ProcessId = $TargetPid" -ErrorAction Stop
    }
    else {
        Get-CimInstance Win32_Process -Filter "Name = 'cod.exe'" -ErrorAction Stop |
            Sort-Object CreationDate -Descending |
            Select-Object -First 1
    }
    if ($null -eq $target -or $target.Name -ne 'cod.exe') {
        throw 'The selected target PID is not an active cod.exe process.'
    }
    $script:ResolvedTargetPid = [int] $target.ProcessId

    $driver = Get-CimInstance Win32_SystemDriver -Filter "Name = 'atvi-randgrid_sr'" -ErrorAction Stop
    if ($driver.State -ne 'Running') {
        throw "atvi-randgrid_sr is not running (state: $($driver.State))."
    }
    $driverPath = Resolve-DriverPath -PathName $driver.PathName
    if (-not (Test-Path -LiteralPath $driverPath -PathType Leaf)) {
        throw "Running Randgrid driver path is unavailable: $driverPath"
    }
    $driverItem = Get-Item -LiteralPath $driverPath
    $driverHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $driverPath).Hash
    $driverSignature = Get-AuthenticodeSignature -LiteralPath $driverPath

    $processes = Get-CimInstance Win32_Process |
        Where-Object { $_.Name -match '^(cod|bootstrapper|CODBrokerService|codCrashHandler)\.exe$' } |
            Select-Object ProcessId, ParentProcessId, Name, CreationDate
    $processInventory = Get-CimInstance Win32_Process |
        Select-Object ProcessId, ParentProcessId, Name, CreationDate

    [ordered]@{
        schema_version = 1
        captured_utc = [DateTimeOffset]::UtcNow.ToString('o')
        administrator = $true
        target_pid = $script:ResolvedTargetPid
        driver = [ordered]@{
            service_name = $driver.Name
            state = $driver.State
            start_mode = $driver.StartMode
            file_name = $driverItem.Name
            file_size = $driverItem.Length
            sha256 = $driverHash
            signature_status = [string] $driverSignature.Status
            signer = if ($driverSignature.SignerCertificate) {
                $driverSignature.SignerCertificate.Subject
            }
            else {
                $null
            }
        }
        processes = @($processes)
        process_inventory = @($processInventory)
        trace = [ordered]@{
            duration_seconds = $DurationSeconds
            handle_interval_seconds = $HandleIntervalSeconds
            sessions = @(
                [ordered]@{
                    name = $script:AuditSessionName
                    provider = 'Microsoft-Windows-Kernel-Audit-API-Calls'
                    keywords = '0x0'
                    level = '0x4'
                },
                [ordered]@{
                    name = $script:ProcessSessionName
                    provider = 'Microsoft-Windows-Kernel-Process'
                    keywords = '0x50'
                    level = '0x4'
                },
                [ordered]@{
                    name = $script:ObSessionName
                    provider = 'independent SystemTraceProvider session'
                    flags = 'PROC_THREAD+LOADER+OB_HANDLE'
                }
            )
            privacy = 'Raw ETL/dumps remain local and are excluded from Git.'
            safety = 'No process handle is opened to cod.exe; no device or service operation is performed.'
        }
    } | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $preflightPath -Encoding utf8

    Write-CaptureStatus -Phase 'starting' -Message 'Starting three uniquely named ETW sessions and passive handle snapshots.'

    & logman.exe create trace $script:AuditSessionName `
        -p 'Microsoft-Windows-Kernel-Audit-API-Calls' 0x0 0x4 `
        -o $auditEtlPath -f bincirc -max 128 -bs 64 -nb 16 64 -ets
    if ($LASTEXITCODE -ne 0) {
        throw "logman failed to start session $($script:AuditSessionName) (exit $LASTEXITCODE)."
    }
    $auditSessionStarted = $true

    & logman.exe create trace $script:ProcessSessionName `
        -p 'Microsoft-Windows-Kernel-Process' 0x50 0x4 `
        -o $processEtlPath -f bincirc -max 128 -bs 64 -nb 16 64 -ets
    if ($LASTEXITCODE -ne 0) {
        throw "logman failed to start session $($script:ProcessSessionName) (exit $LASTEXITCODE)."
    }
    $processSessionStarted = $true

    & $tracelogPath -start $script:ObSessionName -f $obEtlPath -cir 256 `
        -b 64 -min 32 -max 128 -UsePerfCounter -systemlogger -independent `
        -eflag PROC_THREAD+LOADER+OB_HANDLE
    if ($LASTEXITCODE -ne 0) {
        throw "tracelog failed to start session $($script:ObSessionName) (exit $LASTEXITCODE)."
    }
    $obSessionStarted = $true

    $snapshotArguments = '"' + $handleScript + '" --output "' + $handlesPath +
        '" --duration ' + $DurationSeconds + ' --interval ' + $HandleIntervalSeconds
    $snapshotProcess = Start-Process -FilePath $PythonPath `
        -ArgumentList $snapshotArguments -PassThru -WindowStyle Hidden

    Write-CaptureStatus -Phase 'recording' -Message 'Passive ETW and process-handle snapshots are recording.' `
        -Extra @{ snapshot_pid = $snapshotProcess.Id; duration_seconds = $DurationSeconds }

    for ($elapsed = 0; $elapsed -lt $DurationSeconds; $elapsed++) {
        Start-Sleep -Seconds 1
        $targetStillRunning = Get-CimInstance Win32_Process -Filter "ProcessId = $($script:ResolvedTargetPid)" -ErrorAction SilentlyContinue
        if ($null -eq $targetStillRunning) {
            throw 'The observed cod.exe process exited during the bounded capture.'
        }
        $driverStillRunning = Get-CimInstance Win32_SystemDriver -Filter "Name = 'atvi-randgrid_sr'" -ErrorAction SilentlyContinue
        if ($null -eq $driverStillRunning -or $driverStillRunning.State -ne 'Running') {
            throw 'atvi-randgrid_sr stopped during the bounded capture.'
        }
    }

    & $tracelogPath -stop $script:ObSessionName
    if ($LASTEXITCODE -ne 0) {
        throw "tracelog failed to stop session $($script:ObSessionName) cleanly (exit $LASTEXITCODE)."
    }
    $obSessionStarted = $false

    & logman.exe stop $script:AuditSessionName -ets
    if ($LASTEXITCODE -ne 0) {
        throw "logman failed to stop session $($script:AuditSessionName) cleanly (exit $LASTEXITCODE)."
    }
    $auditSessionStarted = $false

    & logman.exe stop $script:ProcessSessionName -ets
    if ($LASTEXITCODE -ne 0) {
        throw "logman failed to stop session $($script:ProcessSessionName) cleanly (exit $LASTEXITCODE)."
    }
    $processSessionStarted = $false

    if ($snapshotProcess -and -not $snapshotProcess.WaitForExit(30000)) {
        throw "Handle snapshot helper PID $($snapshotProcess.Id) exceeded its internal duration. It was not terminated."
    }
    if ($snapshotProcess -and $snapshotProcess.ExitCode -ne 0) {
        throw "Handle snapshot helper PID $($snapshotProcess.Id) exited with code $($snapshotProcess.ExitCode)."
    }

    Write-CaptureStatus -Phase 'decoding' -Message 'Decoding ETL locally; raw output remains Git-ignored.'

    & $xperfPath -i $auditEtlPath -o $auditDumpPath -a dumper -add_fieldnames -add_rawdata
    $auditXperfDumpExit = $LASTEXITCODE
    & tracerpt.exe $auditEtlPath -o $auditCsvPath -of CSV -summary $auditSummaryPath -y
    $auditTracerptExit = $LASTEXITCODE

    & $xperfPath -i $processEtlPath -o $processDumpPath -a dumper -add_fieldnames -add_rawdata
    $processXperfDumpExit = $LASTEXITCODE
    & tracerpt.exe $processEtlPath -o $processCsvPath -of CSV -summary $processSummaryPath -y
    $processTracerptExit = $LASTEXITCODE

    & $xperfPath -i $obEtlPath -o $obDumpPath -a dumper -add_fieldnames -add_rawdata
    $obXperfDumpExit = $LASTEXITCODE
    & tracerpt.exe $obEtlPath -o $obCsvPath -of CSV -summary $obSummaryPath -y
    $obTracerptExit = $LASTEXITCODE

    $decoderExitCodes = @(
        $auditXperfDumpExit,
        $auditTracerptExit,
        $processXperfDumpExit,
        $processTracerptExit,
        $obXperfDumpExit,
        $obTracerptExit
    )
    if ($decoderExitCodes | Where-Object { $_ -ne 0 }) {
        throw "One or more ETL decoders failed: $($decoderExitCodes -join ', ')."
    }

    Write-CaptureStatus -Phase 'complete' -Message 'Bounded passive capture completed.' -Extra @{
        audit_etl_path = $auditEtlPath
        process_etl_path = $processEtlPath
        handle_snapshot_path = $handlesPath
        audit_xperf_dump_path = $auditDumpPath
        audit_tracerpt_csv_path = $auditCsvPath
        audit_xperf_dump_exit_code = $auditXperfDumpExit
        audit_tracerpt_exit_code = $auditTracerptExit
        process_xperf_dump_path = $processDumpPath
        process_tracerpt_csv_path = $processCsvPath
        process_xperf_dump_exit_code = $processXperfDumpExit
        process_tracerpt_exit_code = $processTracerptExit
        ob_etl_path = $obEtlPath
        ob_xperf_dump_path = $obDumpPath
        ob_tracerpt_csv_path = $obCsvPath
        ob_xperf_dump_exit_code = $obXperfDumpExit
        ob_tracerpt_exit_code = $obTracerptExit
        driver_sha256 = $driverHash
    }
}
catch {
    Write-CaptureStatus -Phase 'failed' -Message $_.Exception.Message -Extra @{
        exception_type = $_.Exception.GetType().FullName
        snapshot_pid = if ($snapshotProcess) { $snapshotProcess.Id } else { $null }
    }
    throw
}
finally {
    if ($auditSessionStarted) {
        # Stop only the exact session created by this invocation. Existing
        # system/kernel loggers are never modified.
        & logman.exe stop $script:AuditSessionName -ets 2>$null | Out-Null
    }
    if ($processSessionStarted) {
        & logman.exe stop $script:ProcessSessionName -ets 2>$null | Out-Null
    }
    if ($obSessionStarted) {
        & $tracelogPath -stop $script:ObSessionName 2>$null | Out-Null
    }
}
