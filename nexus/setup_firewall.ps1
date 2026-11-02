# Run ONCE, in PowerShell opened as Administrator:
#   powershell -ExecutionPolicy Bypass -File .\setup_firewall.ps1
#
# Opens the NEXUS ports ONLY for devices on your own local network (hotspot / Wi-Fi subnet).
# It also removes the older "NEXUS Dev" rule, which allowed ANY address to reach port 8000.

$ErrorActionPreference = "Stop"

Get-NetFirewallRule -DisplayName "NEXUS Dev" -ErrorAction SilentlyContinue | Remove-NetFirewallRule
Get-NetFirewallRule -DisplayName "NEXUS (local network only)" -ErrorAction SilentlyContinue | Remove-NetFirewallRule

New-NetFirewallRule -DisplayName "NEXUS (local network only)" `
    -Direction Inbound -Protocol TCP -LocalPort 8000,8443 `
    -RemoteAddress LocalSubnet -Profile Any -Action Allow | Out-Null

Write-Host "Done. Ports 8000 (certificate setup) and 8443 (NEXUS) are open to your local subnet only."
Write-Host "Check:  Get-NetFirewallRule -DisplayName 'NEXUS*' | Get-NetFirewallAddressFilter"
