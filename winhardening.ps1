# Enable Windows Update
Set-Service -Name wuauserv -StartupType Automatic
Start-Service -Name wuauserv

# Enable Windows Firewall
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True

# Enable Windows Defender
Set-MpPreference -DisableRealtimeMonitoring $false

# Enumerate all users and passwords into a file
$users = Get-LocalUser
$secureString = ConvertTo-SecureString "Password123!" -AsPlainText -Force
$users | ForEach-Object {
    $user = $_
    $credential = New-Object System.Management.Automation.PSCredential ($user.Name, $secureString)
    $user | Select-Object Name, Password | Export-Csv -Path C:\userPasswords.txt -NoTypeInformation -Append
}

# Auto change passwords
$users = Get-LocalUser | Where-Object { $_.Name -ne "Administrator" }
$specialChars = '@#$%&!?:*^-+=<>~'

foreach ($user in $users) {
  # Generate a strong, complex password
  $password = [System.Web.Security.Membership]::GeneratePassword(24, 10)

  # Add special characters to the password
  for ($i = 0; $i -lt 3; $i++) {
    $password = $password.Insert([int](Get-Random -Minimum 0 -Maximum ($password.Length - 1)), $specialChars[Get-Random -Minimum 0 -Maximum ($specialChars.Length - 1)])
  }

  # Update the user password
  $secureString = ConvertTo-SecureString $password -AsPlainText -Force
  Set-LocalUser -Name $user.Name -Password $secureString
}

# Create a document of the new passwords
$passwords = @()
foreach ($user in $users) {
  $passwords += New-Object PSObject -Property @{
    User = $user.Name
    Password = $password
  }
}
$passwords | Export-Csv -Path C:\newPasswords.txt -NoTypeInformation

# Disable guest account
net user guest /active:no

# Disable the built-in administrator account
net user administrator /active:no

# Create an alternative administrator account
$secureString = ConvertTo-SecureString "NewPassword123!" -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential("AlternateAdmin", $secureString)
New-LocalUser -Name "AlternateAdmin" -Password $credential -PasswordNeverExpires 1 -UserMayNotChangePassword 1 -AccountNeverExpires 1
Add-LocalGroupMember -Group "Administrators" -Member "AlternateAdmin"

# Disable unnecessary services
Get-Service | Where-Object {$_.StartType -eq "Automatic" -and $_.DisplayName -notmatch "Windows Server" -and $_.DisplayName -notmatch "Active Directory" -and $_.DisplayName -notmatch "Remote Procedure Call" -and $_.DisplayName -notmatch "DNS Client" -and $_.DisplayName -notmatch "Network Connections" -and $_.DisplayName -notmatch "Task Scheduler" -and $_.DisplayName -notmatch "Plug and Play" -and $_.DisplayName -notmatch "Windows Installer"} | Set-Service -StartupType Disabled
$unnecessaryServices | Set-Service -StartupType Disabled
$unnecessaryServices | Select-Object DisplayName | Export-Csv -Path C:\unnecessaryServices.txt -NoTypeInformation


# Enable File and Printer Sharing firewall exception
New-NetFirewallRule -DisplayName "File and Printer Sharing (Echo Request - ICMPv4-In)" -Direction Inbound –Protocol ICMPv4 –IcmpType 8 –Action Allow

# Configure audit policy
Auditpol.exe /set /subcategory:"Filtering Platform Packet Drop" /success:enable /failure:enable
Auditpol.exe /set /subcategory:"Filtering Platform Connection" /success:enable /failure:enable
Auditpol.exe /set /subcategory:"Special Logon" /success:enable /failure:enable
Auditpol.exe /set /subcategory:"Other Logon/Logoff Events" /success:enable /failure:enable
Auditpol.exe /set /subcategory:"Account Management" /success:enable /failure:enable
Auditpol.exe /set /subcategory:"DS Access" /success:enable /failure:enable
Auditpol.exe /set /subcategory:"Directory Service Changes" /success:enable /failure:enable
Auditpol.exe /set /subcategory:"Account Logon" /success:enable /failure:enable


# Remove administrative shares
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v AutoShareWks /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa" /v forceguest /t REG_DWORD /d 0 /f

# Disable Remote UAC
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 0 /f
