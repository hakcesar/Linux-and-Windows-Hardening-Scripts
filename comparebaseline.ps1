# Script to compare the current configuration against the baseline

# Load the baseline configuration from the text file
$baseline = Get-Content -Path 'C:\baseline_config.txt' | ConvertFrom-String

# Get the current local user accounts and compare against the baseline
$currentUsers = Get-LocalUser | Where-Object { $_.Name -ne "Administrator" }
if ($currentUsers -ne $baseline.UserAccounts) {
    Write-Host 'The current local user accounts do not match the baseline'
}

# Get the current status of Windows firewall and compare against the baseline
$currentFirewallStatus = (Get-NetFirewallProfile).Enabled
if ($currentFirewallStatus -ne $baseline.FirewallStatus) {
    Write-Host 'The current status of Windows firewall does not match the baseline'
}

# Get the current status of Windows Defender and compare against the baseline
$currentDefenderStatus = (Get-MpComputerStatus).AntivirusEnabled
if ($currentDefenderStatus -ne $baseline.DefenderStatus) {
    Write-Host 'The current status of Windows Defender does not match the baseline'
}

# Get the current list of Windows services and compare against the baseline
$currentServices = Get-Service | Select-Object -Property Name, DisplayName, Status
if ($currentServices -ne $baseline.Services) {
    Write-Host 'The current list of Windows services does not match the baseline'
}

Write-Host 'Comparison of current configuration against the baseline has been completed successfully'