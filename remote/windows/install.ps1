# Logwatch Dashboard (module "windows"): install Fluent Bit as a service and ship Windows events to the board.
# Run in an elevated PowerShell on the Windows host, from this folder:
#   .\install.ps1 -Board 192.0.2.10 [-Port 24224] [-Dns] [-Version 5.2.0] [-Sha256 <hash of the zip>]
#   -Dns   also ship the DNS server debug log (C:\Windows\System32\dns\dns.log; enable "Log packets for debugging" in
#          DNS Manager → server Properties → Debug Logging: Outgoing+Incoming, UDP+TCP, Queries, Request, details off)
# Uninstall: Stop-Service fluent-bit; sc.exe delete fluent-bit; Remove-Item 'C:\Program Files\fluent-bit' -Recurse
param(
  [Parameter(Mandatory)][string]$Board,
  [int]$Port = 24224,
  [switch]$Dns,
  [string]$Version = '5.2.0',
  [string]$Sha256 = ''
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$dst = 'C:\Program Files\fluent-bit'
if (-not (Test-Path "$dst\bin\fluent-bit.exe")) {
  $tmp = Join-Path $env:TEMP "lw-fb-$Version"
  New-Item -ItemType Directory -Force $tmp | Out-Null
  $zip = Join-Path $tmp 'fluent-bit.zip'
  $mm = $Version.Split('.')[0..1] -join '.'
  Invoke-WebRequest "https://packages.fluentbit.io/windows/fluent-bit-$Version-win64.zip" -OutFile $zip -UseBasicParsing
  $h = (Get-FileHash $zip -Algorithm SHA256).Hash
  if ($Sha256 -and $h -ne $Sha256.ToUpper()) { throw "zip hash mismatch: $h" }
  "fluent-bit $Version zip SHA256 $h (compare with https://packages.fluentbit.io/windows/ or the $mm release notes)"
  Expand-Archive $zip -DestinationPath "$tmp\x" -Force
  $inner = Get-ChildItem "$tmp\x" -Directory | Select-Object -First 1
  Move-Item $inner.FullName $dst
  Remove-Item $tmp -Recurse -Force
}
New-Item -ItemType Directory -Force 'C:\ProgramData\fluent-bit\storage' | Out-Null
Copy-Item "$here\logwatch.lua" "$dst\conf\logwatch.lua" -Force
$tpl = if ($Dns) { 'agent-dns.yaml' } else { 'agent.yaml' }
(Get-Content "$here\$tpl" -Raw).Replace('@BOARD@', $Board).Replace('@PORT@', "$Port") |
  Set-Content "$dst\conf\logwatch.yaml" -Encoding ascii
$t = cmd /c "`"$dst\bin\fluent-bit.exe`" -c `"$dst\conf\logwatch.yaml`" --dry-run 2>&1"
if ($LASTEXITCODE -ne 0) { $t | Select-Object -Last 5; throw 'fluent-bit config test failed' }
if (-not (Get-Service fluent-bit -ErrorAction SilentlyContinue)) {
  New-Service -Name fluent-bit -DisplayName 'Fluent Bit (Logwatch Dashboard)' -StartupType Automatic `
    -BinaryPathName "`"$dst\bin\fluent-bit.exe`" -c `"$dst\conf\logwatch.yaml`"" | Out-Null
  sc.exe failure fluent-bit reset= 86400 actions= restart/60000/restart/60000/restart/60000 | Out-Null
}
Restart-Service fluent-bit
Start-Sleep 5
"$env:COMPUTERNAME fluent-bit: $((Get-Service fluent-bit).Status) → ${Board}:$Port"
