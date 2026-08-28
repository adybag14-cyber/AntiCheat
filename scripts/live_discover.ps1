$ErrorActionPreference = 'SilentlyContinue'
Write-Output "=== ADMIN LEVEL ==="
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$pr = New-Object Security.Principal.WindowsPrincipal($id)
Write-Output ("IsAdmin: " + $pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))

Write-Output ""
Write-Output "=== RICOCHET PROCESSES ==="
Get-CimInstance Win32_Process | Where-Object {
  $_.Name -match 'cod|bootstrapper|broker|randgrid|telescope|attestation|crash'
} | ForEach-Object {
  Write-Output ("{0,-40} PID={1,-8} PPID={2}" -f $_.Name, $_.ProcessId, $_.ParentProcessId)
}

Write-Output ""
Write-Output "=== RANDGRID SERVICE ==="
Get-CimInstance Win32_Service | Where-Object { $_.Name -match 'randgrid|ricochet|cod' -or $_.DisplayName -match 'randgrid|ricochet|cod' } | ForEach-Object {
  Write-Output ("Name={0}  State={1}  StartMode={2}" -f $_.Name, $_.State, $_.StartMode)
  Write-Output ("  Path={0}" -f $_.PathName)
}

Write-Output ""
Write-Output "=== KERNEL DRIVERS (randgrid/ricochet/cod) ==="
Get-CimInstance Win32_SystemDriver | Where-Object { $_.Name -match 'randgrid|ricochet|cod' -or $_.DisplayName -match 'randgrid|ricochet|cod' } | ForEach-Object {
  Write-Output ("Driver={0}  State={1}  Start={2}" -f $_.Name, $_.State, $_.StartMode)
  Write-Output ("  Path={0}" -f $_.PathName)
}

Write-Output ""
Write-Output "=== RANDGRID DEVICE OBJECTS ==="
$devs = Get-CimInstance Win32_PnPEntity | Where-Object { $_.Name -match 'randgrid' }
if ($devs) { $devs | ForEach-Object { Write-Output $_.Name } } else { Write-Output "(no PnP entity named randgrid)" }
# Check for the device file
foreach ($p in @('\\.\Randgrid','\\.\Global\Randgrid','\\.\GLOBALROOT\Device\Randgrid')) {
  $f = Get-Item $p -ErrorAction SilentlyContinue
  if ($f) { Write-Output ("Device file exists: {0}" -f $p) }
}

Write-Output ""
Write-Output "=== BROKER NAMED PIPE ==="
$pipe = '\\.\pipe\COD.Broker.v1'
$pf = Get-Item $pipe -ErrorAction SilentlyContinue
if ($pf) { Write-Output ("Pipe exists: {0}" -f $pipe) } else { Write-Output ("Pipe NOT present: {0}" -f $pipe) }
# list all COD pipes
Get-ChildItem '\\.\pipe\' -ErrorAction SilentlyContinue | Where-Object { $_.Name -match 'cod|broker|randgrid' } | ForEach-Object { Write-Output ("  pipe: {0}" -f $_.Name) }

Write-Output ""
Write-Output "=== GAME MODULES (cod.exe) ==="
$cod = Get-Process cod -ErrorAction SilentlyContinue
if ($cod) {
  Write-Output ("cod.exe PID={0}  Modules={1}" -f $cod.Id, $cod.Modules.Count)
  $cod.Modules | Where-Object { $_.ModuleName -match 'randgrid|ricochet|cod|telescope|broker|attest|crash|hook' } | ForEach-Object {
    Write-Output ("  {0,-40} base={1:X}  size={2}" -f $_.ModuleName, $_.BaseAddress, $_.ModuleMemorySize)
  }
} else { Write-Output "(cod.exe not running)" }

Write-Output ""
Write-Output "=== DRIVER BASE ADDRESSES (via ntdll / driver list) ==="
# Use the driver list from the kernel via a quick P/Invoke-free approach: sc + registry
Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services' | Where-Object { $_.PSChildName -match 'randgrid|ricochet' } | ForEach-Object {
  $svc = Get-Item $_.PSPath
  $img = $svc.GetValue('ImagePath')
  $start = $svc.GetValue('Start')
  Write-Output ("Svc={0} Start={1} Image={2}" -f $_.PSChildName, $start, $img)
}
