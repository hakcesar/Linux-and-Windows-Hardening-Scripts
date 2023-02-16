# Script to set a baseline configuration in a text file

# Get local users and exclude the Administrator account
$users = Get-LocalUser | Where-Object { $_.Name -ne "Administrator" }

# Get the status of Windows firewall
$firewallStatus = (Get-NetFirewallProfile).Enabled

# Get the status of Windows Defender
$defenderStatus = (Get-MpComputerStatus).AntivirusEnabled

# Get the list of Windows services
$services = Get-Service | Select-Object -Property Name, DisplayName, Status

# Store the baseline configuration in a text file
$baseline = @{
    'UserAccounts' = $users
    'FirewallStatus' = $firewallStatus
    'DefenderStatus' = $defenderStatus
    'Services' = $services
}

$baseline | ConvertTo-String | Out-File -FilePath 'C:\baseline_config.txt'

Write-Host 'Baseline configuration has been saved successfully to C:\baseline_config.txt'


