#Requires -RunAsAdministrator
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$installPath = "C:\Program Files\OpenSSH"
$tempPath = "C:\Windows\Temp"
cd $tempPath

$programdataPath = "C:\ProgramData"
$fwrule_name = "OpenSSH Server (sshd)"

$repo = "PowerShell/Win32-OpenSSH"
$file = "OpenSSH-Win64.zip"

$releases = "https://api.github.com/repos/$repo/releases"

# Make sure either english or german is the win system locale
switch ($((Get-UICulture)[0].DisplayName)){
  'Deutsch (Deutschland)' {
     Write-Host "$((Get-UICulture)[0].DisplayName) detected, translating ACLs to German"
     $authenticatedUserName = "NT-AUTORITÄT\Authentifizierte Benutzer"
     $systemUserName = "NT-AUTORITÄT\SYSTEM"
     $administratorsUserName = "VORDEFINIERT\Administratoren"
  }
  'English (United States)' {
     Write-Host "$((Get-UICulture)[0].DisplayName) detected, using default ACLs"
     $authenticatedUserName = "NT AUTHORITY\Authenticated Users"
     $systemUserName = "NT AUTHORITY\SYSTEM"
     $administratorsUserName = "BUILTIN\Administrators"
  }
  default {
     Write-Error 'Currently only English and German UI Languages are supported'
     exit 1 
  }
}


Write-Host "Enforce TLS 1.2"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

Write-Host "Determining latest release"
$tag = (Invoke-WebRequest $releases | ConvertFrom-Json)[0].tag_name

$download = "https://github.com/$repo/releases/download/$tag/$file"
$name = $file.Split(".")[0]
$zip = $zip = "$name-$tag.zip"
$dir = "$name-$tag"

Write-Host "Dowloading latest release"
Invoke-WebRequest $download -Out $zip

Write-Host "Extracting release files"
Expand-Archive $zip -Force

# Cleaning up target dir
Remove-Item $name -Recurse -Force -ErrorAction SilentlyContinue 

# Moving from temp dir to target dir
Move-Item $dir\$name -Destination $name -Force

# Removing temp files
Remove-Item $zip -Force
Remove-Item $dir -Recurse -Force

# Check if OpenSSH Folder exists
Write-Host "Checking existence of destination folder"
if(!(Test-Path -path $installPath)) {
  # Create Folder
  Write-Host Creating destination folder
  New-Item -ItemType directory -Path $installPath
} else {
  # Clean Up previous installation
  Write-Host Cleaning up previous installation
  cd $installPath
  .\uninstall-sshd.ps1
}

# Copy contents to correct directory
Write-Host Copy files to install path
Copy-Item -Path "$tempPath\$name\*" -Recurse -Destination $installPath

# Install SSH Daemon
Write-Host Install OpenSSH
cd $installPath
.\install-sshd.ps1

# Check OS
if((((Get-WmiObject Win32_OperatingSystem).Name) -like "Microsoft Windows Server 2012*") -or
   (((Get-WmiObject Win32_OperatingSystem).Name) -like "Microsoft Windows Server 2016*") -or
   (((Get-WmiObject Win32_OperatingSystem).Name) -like "Microsoft Windows Server 2019*") -or
   (((Get-WmiObject Win32_OperatingSystem).Name) -like "Microsoft Windows 10*")){

  # Check if Rule already exists
  $fwrule = Get-NetFirewallRule -DisplayName $fwrule_name

  if($fwrule) {
     Write-Host "Firewall Rule with DisplayName $fwrule_name already exists. Please Check this Rule"
  } else {
     Write-Host "Firewall Rule not Found. Rule will be created"

     # Set Firewall Rule
     New-NetFirewallRule -Name sshd -DisplayName $fwrule_name -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22

     Write-Host "Firewall Rule with DisplayName $fwrule_name was created"
  }

} else {
  # Set Firewall Rule for Windows Client
  netsh advfirewall firewall add rule name=sshd dir=in action=allow protocol=TCP localport=22
}

# Set SSHD to automatic
Set-Service -Name sshd -StartupType Automatic
Write-Host "Set Service sshd to Automatic"

# Start SSHD
Start-Service -Name sshd
Write-Host "Start Service sshd"

# Set Default Shell for SSH
New-ItemProperty -Path "HKLM:\SOFTWARE\OpenSSH" -Name DefaultShell -Value "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -PropertyType String -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\OpenSSH" -Name DefaultShellCommandOption -Value "/c" -PropertyType String -Force
Write-Host "Set Default Shell and Default Command Options for OpenSSH Server"

# Copy Administrator Key file to __PROGRAMDATA__/ssh/administrators_authorized_keys
Copy-Item "$scriptDir\administrators_authorized_keys" -Destination "$programdataPath\ssh\administrators_authorized_keys"
Write-Host "$scriptDir\administrators_authorized_keys has been updated with the local copy"

# Remove Permission Inheritance
$acl = Get-ACL "$programdataPath\ssh\administrators_authorized_keys"
$acl.SetAccessRuleProtection($True, $True)

# Remove Authenticated Users from acl
$accessrule = New-Object system.security.AccessControl.FileSystemAccessRule($authenticatedUserName,"Read","Allow")
$acl.RemoveAccessRuleAll($accessrule)

# Remove All Write and Modify Permissions for System and Administrators
$accessrule = New-Object system.security.AccessControl.FileSystemAccessRule($systemUserName,"Read","Allow")
$acl.RemoveAccessRuleAll($accessrule)
$accessrule = New-Object system.security.AccessControl.FileSystemAccessRule($administratorsUserName,"Read","Allow")
$acl.RemoveAccessRuleAll($accessrule)

# Add FullControl Permissions for System and Administrators
$accessrule = New-Object system.security.AccessControl.FileSystemAccessRule($systemUserName,"FullControl","Allow")
$acl.AddAccessRule($accessrule)
$accessrule = New-Object system.security.AccessControl.FileSystemAccessRule($administratorsUserName,"FullControl","Allow")
$acl.AddAccessRule($accessrule)

# Set Modified ACL on administratorKeysFolder
Set-Acl "$programdataPath\ssh\administrators_authorized_keys" -AclObject $acl
Write-Host "ACL of $programdataPath\ssh\administrators_authorized_keys has been updated to comply with OpenSSH required settings"

# Change default configuration
$sshconfigfile = "$programdataPath\ssh\sshd_config"

# Enable Listen Port 22
$regex = '#Port 22'
(Get-Content $sshconfigfile) -replace $regex, "Port 22" | Set-Content $sshconfigfile

# Change Syslog Facility
$regex = '#SyslogFacility AUTH'
(Get-Content $sshconfigfile) -replace $regex, "SyslogFacility AUTH" | Set-Content $sshconfigfile

# Change Syslog Level
$regex = '#LogLevel INFO'
(Get-Content $sshconfigfile) -replace $regex, "LogLevel ERROR" | Set-Content $sshconfigfile

# Enable PublicKeyAuth
$regex = '#PubkeyAuthentication yes'
(Get-Content $sshconfigfile) -replace $regex, "PubkeyAuthentication yes" | Set-Content $sshconfigfile

# Enable StrictMode
$regex = '#StrictModes yes'
(Get-Content $sshconfigfile) -replace $regex, "StrictModes yes" | Set-Content $sshconfigfile

# Disable Administrator Password Authentication
$regex = '#PermitRootLogin prohibit-password'
(Get-Content $sshconfigfile) -replace $regex, "PermitRootLogin prohibit-password" | Set-Content $sshconfigfile
# Restart SSHD
Restart-Service -Name sshd
Write-Host "OpenSSH Server has been restarted to load updated config"

cd $scriptDir