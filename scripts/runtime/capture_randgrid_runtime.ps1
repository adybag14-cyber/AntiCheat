[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $OutputDirectory,

    [Parameter(Mandatory = $true)]
    [string] $PythonPath,

    [ValidateRange(10, 300)]
    [int] $DurationSeconds = 60,

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
        session_name = $script:SessionName
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
$script:ResolvedTargetPid = $TargetPid
$script:StatusPath = Join-Path $resolvedOutput 'capture-status.json'
$etlPath = Join-Path $resolvedOutput 'kernel-audit.etl'
$dumpPath = Join-Path $resolvedOutput 'kernel-audit-dump.txt'
$csvPath = Join-Path $resolvedOutput 'kernel-audit.csv'
$summaryPath = Join-Path $resolvedOutput 'tracerpt-summary.txt'
$handlesPath = Join-Path $resolvedOutput 'process-handles.jsonl'
$preflightPath = Join-Path $resolvedOutput 'runtime-preflight.json'
$xperfPath = 'C:\Program Files (x86)\Windows Kits\10\Windows Performance Toolkit\xperf.exe'
$handleScript = Join-Path $PSScriptRoot 'snapshot_process_handles.py'
$providerSpec = 'Microsoft-Windows-Kernel-Audit-API-Calls:0xffffffffffffffff:0x4:stack+Microsoft-Windows-Kernel-Process:0x50:0x4'
$sessionStarted = $false
$snapshotProcess = $null

Write-CaptureStatus -Phase 'preflight' -Message 'Validating elevation, target, driver, and tracing tools.'

try {
    if (-not (Test-IsAdministrator)) {
        throw 'Administrator elevation is required for Microsoft-Windows-Kernel-* ETW providers.'
    }
    if (-not (Test-Path -LiteralPath $xperfPath -PathType Leaf)) {
        throw "xperf.exe is unavailable at $xperfPath"
    }
    if (-not (Test-Path -LiteralPath $PythonPath -PathType Leaf)) {
        throw "Python is unavailable at $PythonPath"
    }
    if (-not (Test-Path -LiteralPath $handleScript -PathType Leaf)) {
        throw "Handle snapshot helper is unavailable at $handleScript"
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
        trace = [ordered]@{
            duration_seconds = $DurationSeconds
            session_name = $script:SessionName
            providers = @(
                'Microsoft-Windows-Kernel-Audit-API-Calls',
                'Microsoft-Windows-Kernel-Process'
            )
            privacy = 'Raw ETL/dumps remain local and are excluded from Git.'
            safety = 'No process handle is opened to cod.exe; no device or service operation is performed.'
        }
    } | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $preflightPath -Encoding utf8

    Write-CaptureStatus -Phase 'starting' -Message 'Starting a uniquely named user ETW session and passive handle snapshots.'

    & $xperfPath -start $script:SessionName -on $providerSpec -f $etlPath `
        -FileMode Circular -MaxFile 128 -BufferSize 64 -MinBuffers 16 -MaxBuffers 64
    if ($LASTEXITCODE -ne 0) {
        throw "xperf failed to start session $($script:SessionName) (exit $LASTEXITCODE)."
    }
    $sessionStarted = $true

    $snapshotArguments = '"' + $handleScript + '" --output "' + $handlesPath +
        '" --duration ' + $DurationSeconds + ' --interval 0.5'
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

    & $xperfPath -stop $script:SessionName
    if ($LASTEXITCODE -ne 0) {
        throw "xperf failed to stop session $($script:SessionName) cleanly (exit $LASTEXITCODE)."
    }
    $sessionStarted = $false

    if ($snapshotProcess -and -not $snapshotProcess.WaitForExit(30000)) {
        throw "Handle snapshot helper PID $($snapshotProcess.Id) exceeded its internal duration. It was not terminated."
    }
    if ($snapshotProcess -and $snapshotProcess.ExitCode -ne 0) {
        throw "Handle snapshot helper PID $($snapshotProcess.Id) exited with code $($snapshotProcess.ExitCode)."
    }

    Write-CaptureStatus -Phase 'decoding' -Message 'Decoding ETL locally; raw output remains Git-ignored.'

    & $xperfPath -i $etlPath -o $dumpPath -a dumper `
        -provider e02a841c-75a3-4fa7-afc8-ae09cf9b7f23 22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716 `
        -add_fieldnames -add_rawdata
    $xperfDumpExit = $LASTEXITCODE

    & tracerpt.exe $etlPath -o $csvPath -of CSV -summary $summaryPath -y
    $tracerptExit = $LASTEXITCODE

    Write-CaptureStatus -Phase 'complete' -Message 'Bounded passive capture completed.' -Extra @{
        etl_path = $etlPath
        handle_snapshot_path = $handlesPath
        xperf_dump_path = $dumpPath
        tracerpt_csv_path = $csvPath
        xperf_dump_exit_code = $xperfDumpExit
        tracerpt_exit_code = $tracerptExit
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
    if ($sessionStarted) {
        # Stop only the exact session created by this invocation. Existing
        # system/kernel loggers are never modified.
        & $xperfPath -stop $script:SessionName 2>$null | Out-Null
    }
}
