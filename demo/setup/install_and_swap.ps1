# Scuffle demo setup (Windows).  Installs MSMQ, swaps in the vulnerable mqqm.dll, verifies the service.
# Run as Administrator.  Assumes fetch_vuln_mqqm.py has produced a local mqqm_vuln.dll (22621.963).
param([string]$VulnDll = ".\mqqm_vuln.dll")

Write-Host "[1/4] Enabling MSMQ-Server feature ..."
Enable-WindowsOptionalFeature -Online -FeatureName MSMQ-Server -All -NoRestart -EA Stop | Out-Null
Write-Host "      (a reboot may be required before mqsvc listens on TCP 1801)"

Write-Host "[2/4] Stopping MSMQ so mqqm.dll is not in use ..."
Stop-Service MSMQ -Force -EA SilentlyContinue; Start-Sleep 3

Write-Host "[3/4] Swapping in the vulnerable mqqm.dll (takeown + overwrite; WFP reverts boot-rename) ..."
$sys = "$env:WINDIR\System32\mqqm.dll"
takeown /f $sys | Out-Null
icacls $sys /grant "Administrators:F" | Out-Null
Copy-Item $sys "$sys.orig" -Force -EA SilentlyContinue
Copy-Item $VulnDll $sys -Force
Write-Host ("      now: " + (Get-Item $sys).VersionInfo.FileVersion + "  (want 10.0.22621.963)")

Write-Host "[4/4] Starting MSMQ ..."
Start-Service MSMQ -EA SilentlyContinue; Start-Sleep 4
$p = Get-Process mqsvc -EA SilentlyContinue
$m = $p.Modules | Where-Object { $_.ModuleName -eq "mqqm.dll" }
Write-Host ("      mqsvc pid=" + $p.Id + "  loaded mqqm=" + $m.FileVersionInfo.FileVersion)
Write-Host "[done] If loaded mqqm = 22621.963 and mqsvc is running, the target is ready."
