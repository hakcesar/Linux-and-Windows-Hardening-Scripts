# Enable Windows Update
Set-Service -Name wuauserv -StartupType Automatic
Start-Service -Name wuauserv

# Enable Windows Firewall

netsh advfirewall set allprofiles state on

# Enable Windows Defender

Set-MpPreference -DisableRealtimeMonitoring $false

# Enumerate all users and passwords into a file

$users = Get-WmiObject -Class Win32_UserAccount
$secureString = ConvertTo-SecureString "Password123!" -AsPlainText -Force
$users | ForEach-Object {
$user = $_
$credential = New-Object System.Management.Automation.PSCredential ($user.Name, $secureString)
$user | Select-Object Name, Password | Export-Csv -Path C:\userPasswords.txt -NoTypeInformation -Append
}

# Auto change passwords

$users = Get-WmiObject -Class Win32_UserAccount | Where-Object { $_.Name -ne "Administrator" }
$specialChars = '@#$%&!?:*^-+=<>~'

foreach ($user in $users) {

# Generate a strong, complex password

$password = [System.Web.Security.Membership]::GeneratePassword(24, 10)

# Add special characters to the password

for ($i = 0; $i -lt 3; $i++) {
$password = $password.Insert([int](Get-Random -Minimum 0 -Maximum ($password.Length - 1)), $specialChars[Get-Random -Minimum 0 -Maximum ($specialChars.Length - 1)])
}

# Update the users password

$secureString = ConvertTo-SecureString $password -AsPlainText -Force
([adsi]"WinNT://localhost/$($user.Name),user").psbase.invoke("SetPassword",$secureString)
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

#Disable the built-in administrator account

net user administrator /active:no

# Create an alternative administrator account

$secureString = ConvertTo-SecureString "NewPassword123!" -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential("AlternateAdmin", $secureString)
$computer = [ADSI]"WinNT://localhost"
$user = $computer.Create("User", "AlternateAdmin")
$user.SetPassword($secureString)
$user.Put("PasswordExpired", 0)
$user.SetInfo()

$objGroup = [ADSI]"WinNT://localhost/Administrators"
$objGroup.Add("WinNT://$env:COMPUTERNAME/AlternateAdmin")

# Disable unnecessary services

Get-Service | Where-Object {$.StartType -eq "Automatic" -and $.DisplayName -notmatch 
"Windows Server" -and $.DisplayName -notmatch "Active Directory" -and $.DisplayName 
-notmatch "Remote Procedure Call" -and $.DisplayName -notmatch "DNS Client" -and 
$.DisplayName -notmatch "Network Connections" -and $.DisplayName -notmatch 
"Task Scheduler" -and $.DisplayName -notmatch "Plug and Play" -and 
$_.DisplayName -notmatch "Windows Installer"} | Set-Service -StartupType Disabled

# Enable File and Printer Sharing firewall exception
netsh advfirewall firewall set rule group="File and Printer Sharing" new enable=Yes

# Configure audit policy
auditpol.exe /set /subcategory:"Filtering Platform Packet Drop" /success:enable /failure:enable
