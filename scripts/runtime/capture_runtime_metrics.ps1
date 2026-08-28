[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $OutputDirectory,

    [Parameter(Mandatory = $true)]
    [string] $PythonPath,

    [ValidateRange(10, 300)]
    [int] $DurationSeconds = 30,

    [int] $TargetPid = 0
)

$ErrorActionPreference = 'Stop'
$resolvedOutput = [System.IO.Path]::GetFullPath($OutputDirectory)
New-Item -ItemType Directory -Force -Path $resolvedOutput | Out-Null

$metricsPath = Join-Path $resolvedOutput 'process-metrics.csv'
$handlesPath = Join-Path $resolvedOutput 'process-handles.jsonl'
$summaryPath = Join-Path $resolvedOutput 'runtime-summary.json'
$statusPath = Join-Path $resolvedOutput 'metrics-status.json'
$handleScript = Join-Path $PSScriptRoot 'snapshot_process_handles.py'

function Write-MetricsStatus {
    param([string] $Phase, [string] $Message = '')

    [ordered]@{
        schema_version = 1
        phase = $Phase
        message = $Message
        updated_utc = [DateTimeOffset]::UtcNow.ToString('o')
        target_pid = $script:ResolvedTargetPid
    } | ConvertTo-Json | Set-Content -LiteralPath $statusPath -Encoding utf8
}

function Resolve-DriverPath {
    param([string] $PathName)

    if ($PathName.StartsWith('\??\')) {
        return $PathName.Substring(4)
    }
    return $PathName
}

function Get-Statistics {
    param([double[]] $Values)

    if ($Values.Count -eq 0) {
        return $null
    }
    $measure = $Values | Measure-Object -Minimum -Maximum -Average
    return [ordered]@{
        min = [double] $measure.Minimum
        max = [double] $measure.Maximum
        mean = [double] $measure.Average
    }
}

$script:ResolvedTargetPid = $TargetPid
$snapshotProcess = $null
Write-MetricsStatus -Phase 'preflight' -Message 'Validating target and running driver.'

try {
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
    $driverItem = Get-Item -LiteralPath $driverPath -ErrorAction Stop
    $driverHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $driverPath).Hash
    $driverSignature = Get-AuthenticodeSignature -LiteralPath $driverPath

    $startedUtc = [DateTimeOffset]::UtcNow
    $relatedAtStart = Get-CimInstance Win32_Process |
        Where-Object { $_.Name -match '^(cod|bootstrapper|CODBrokerService|codCrashHandler)\.exe$' } |
        Select-Object ProcessId, ParentProcessId, Name, CreationDate

    $snapshotArguments = '"' + $handleScript + '" --output "' + $handlesPath +
        '" --duration ' + $DurationSeconds + ' --interval 0.5'
    $snapshotProcess = Start-Process -FilePath $PythonPath -ArgumentList $snapshotArguments `
        -PassThru -WindowStyle Hidden

    Write-MetricsStatus -Phase 'recording' -Message 'Collecting passive process metrics and process-handle metadata.'

    $samples = [System.Collections.Generic.List[object]]::new()
    $previousCpu = $null
    $previousTimestamp = $null

    for ($index = 0; $index -lt $DurationSeconds; $index++) {
        $process = Get-Process -Id $script:ResolvedTargetPid -ErrorAction Stop
        $cim = Get-CimInstance Win32_Process -Filter "ProcessId = $($script:ResolvedTargetPid)" -ErrorAction Stop
        $timestamp = [DateTimeOffset]::UtcNow
        $cpuSeconds = [double] $process.CPU
        $cpuDelta = if ($null -ne $previousCpu) { $cpuSeconds - $previousCpu } else { 0.0 }
        $wallDelta = if ($null -ne $previousTimestamp) {
            ($timestamp - $previousTimestamp).TotalSeconds
        }
        else {
            0.0
        }

        $sample = [pscustomobject]@{
            timestamp_utc = $timestamp.ToString('o')
            pid = $script:ResolvedTargetPid
            threads = $process.Threads.Count
            handles = $process.HandleCount
            working_set_bytes = $process.WorkingSet64
            private_memory_bytes = $process.PrivateMemorySize64
            cpu_total_seconds = $cpuSeconds
            cpu_delta_seconds = $cpuDelta
            wall_delta_seconds = $wallDelta
            read_operations = [uint64] $cim.ReadOperationCount
            write_operations = [uint64] $cim.WriteOperationCount
            other_operations = [uint64] $cim.OtherOperationCount
            read_bytes = [uint64] $cim.ReadTransferCount
            write_bytes = [uint64] $cim.WriteTransferCount
            other_bytes = [uint64] $cim.OtherTransferCount
        }
        $samples.Add($sample)
        $sample | Export-Csv -LiteralPath $metricsPath -NoTypeInformation -Append
        $previousCpu = $cpuSeconds
        $previousTimestamp = $timestamp
        Start-Sleep -Seconds 1
    }

    if ($snapshotProcess -and -not $snapshotProcess.WaitForExit(30000)) {
        throw "Handle snapshot helper PID $($snapshotProcess.Id) exceeded its internal duration. It was not terminated."
    }
    if ($snapshotProcess -and $snapshotProcess.ExitCode -ne 0) {
        throw "Handle snapshot helper PID $($snapshotProcess.Id) exited with code $($snapshotProcess.ExitCode)."
    }

    $completedUtc = [DateTimeOffset]::UtcNow
    $relatedAtEnd = Get-CimInstance Win32_Process |
        Where-Object { $_.Name -match '^(cod|bootstrapper|CODBrokerService|codCrashHandler)\.exe$' } |
        Select-Object ProcessId, ParentProcessId, Name, CreationDate

    $eventSince = $startedUtc.AddHours(-12).LocalDateTime
    $collisionEvents = Get-WinEvent -FilterHashtable @{ LogName = 'System'; StartTime = $eventSince } -ErrorAction SilentlyContinue |
        Where-Object {
            $_.Id -eq 7000 -and
            $_.Message -match 'atvi-randgrid_msstore' -and
            $_.Message -match 'already exists'
        } |
        Sort-Object TimeCreated
    $intervals = [System.Collections.Generic.List[double]]::new()
    for ($eventIndex = 1; $eventIndex -lt $collisionEvents.Count; $eventIndex++) {
        $intervals.Add(
            ($collisionEvents[$eventIndex].TimeCreated - $collisionEvents[$eventIndex - 1].TimeCreated).TotalSeconds
        )
    }

    $handleSummary = $null
    if (Test-Path -LiteralPath $handlesPath) {
        $lastHandleLine = Get-Content -LiteralPath $handlesPath -Tail 1 | ConvertFrom-Json
        if ($lastHandleLine.type -eq 'summary') {
            $handleSummary = $lastHandleLine
        }
    }

    [ordered]@{
        schema_version = 1
        capture = [ordered]@{
            started_utc = $startedUtc.ToString('o')
            completed_utc = $completedUtc.ToString('o')
            duration_seconds_requested = $DurationSeconds
            sample_count = $samples.Count
            administrator = $false
            privacy = 'Raw metrics and handle metadata remain local and are excluded from Git.'
            safety = 'No process handle was opened to cod.exe; no driver, device, service, or game mutation occurred.'
        }
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
        target = [ordered]@{
            pid = $script:ResolvedTargetPid
            process_name = 'cod.exe'
            creation_time = $target.CreationDate
            threads = Get-Statistics -Values ([double[]] $samples.threads)
            handles = Get-Statistics -Values ([double[]] $samples.handles)
            working_set_bytes = Get-Statistics -Values ([double[]] $samples.working_set_bytes)
            private_memory_bytes = Get-Statistics -Values ([double[]] $samples.private_memory_bytes)
            cpu_delta_seconds = Get-Statistics -Values ([double[]] $samples.cpu_delta_seconds)
        }
        components_at_start = @($relatedAtStart)
        components_at_end = @($relatedAtEnd)
        process_handle_snapshots = $handleSummary
        msstore_collision_events = [ordered]@{
            count = $collisionEvents.Count
            first = if ($collisionEvents.Count) { $collisionEvents[0].TimeCreated.ToString('o') } else { $null }
            last = if ($collisionEvents.Count) { $collisionEvents[-1].TimeCreated.ToString('o') } else { $null }
            interval_seconds = Get-Statistics -Values ([double[]] $intervals)
            event_id = 7000
            error = 'Cannot create a file when that file already exists.'
        }
        evidence_limits = @(
            'Non-elevated Windows zeroed kernel object pointers in the handle table.',
            'No Kernel-Audit-API-Calls or OB_HANDLE ETW provider was active.',
            'This capture cannot map a process handle to cod.exe or compare requested and granted access.',
            'Object-callback access stripping remains unproved by this capture.'
        )
    } | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $summaryPath -Encoding utf8

    Write-MetricsStatus -Phase 'complete' -Message 'Bounded non-elevated runtime metrics capture completed.'
}
catch {
    Write-MetricsStatus -Phase 'failed' -Message $_.Exception.Message
    throw
}
