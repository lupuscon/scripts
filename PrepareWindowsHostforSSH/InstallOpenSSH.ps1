#Requires -RunAsAdministrator
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$installPath = "C:\Program Files\OpenSSH"
$tempPath = "C:\Windows\Temp"
cd $tempPath

$programdataPath = "C:\ProgramData"
$administratorKeysFolder = ".ssh"
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

# Check if folder for Administrator SSH Keys exists
Write-Host "Checking existence of folder for Administrators ssh keys exists"
if(!(Test-Path -path "$programdataPath\ssh\$administratorKeysFolder")) {
  # Create Folder
  Write-Host "Creating folder for Administrators ssh keys"
  New-Item -Path "$programdataPath\ssh\" -Name $administratorKeysFolder -ItemType "directory"
} else {
  # Folder already exists
  Write-Host "Folder for Administrators ssh keys already exists, ACLs will be updated to overwrite administrators_authorized_keys"
  $acl = Get-ACL -Path "$programdataPath\ssh\$administratorKeysFolder"
  $accessrule = New-Object system.security.AccessControl.FileSystemAccessRule($administratorsUserName,"FullControl","ContainerInherit,ObjectInherit","none","Allow")
  $acl.AddAccessRule($accessrule)
  
  # Set Modified ACL on administratorKeysFolder
  Set-Acl -Path "$programdataPath\ssh\$administratorKeysFolder" -AclObject $acl
}

# Copy Administrator Key file to __PROGRAMDATA__/ssh/administrators_authorized_keys
Copy-Item "$scriptDir\administrators_authorized_keys" -Destination "$programdataPath\ssh\$administratorKeysFolder\administrators_authorized_keys"
Write-Host "$scriptDir\administrators_authorized_keys has been updated with the local copy"

# Remove Permission Inheritance
$acl = Get-ACL -Path "$programdataPath\ssh\$administratorKeysFolder"
$acl.SetAccessRuleProtection($True, $True)

# Remove Authenticated Users from acl
$accessrule = New-Object system.security.AccessControl.FileSystemAccessRule($authenticatedUserName,"Read",,,"Allow")
$acl.RemoveAccessRuleAll($accessrule)

# Remove All Write and Modify Permissions for System and Administrators
$accessrule = New-Object system.security.AccessControl.FileSystemAccessRule($systemUserName,"Read",,,"Allow")
$acl.RemoveAccessRuleAll($accessrule)
$accessrule = New-Object system.security.AccessControl.FileSystemAccessRule($administratorsUserName,"Read",,,"Allow")
$acl.RemoveAccessRuleAll($accessrule)

# Add Read Only Permissions for System and Administrators
$accessrule = New-Object system.security.AccessControl.FileSystemAccessRule($systemUserName,"Read","ContainerInherit,ObjectInherit","none","Allow")
$acl.AddAccessRule($accessrule)
$accessrule = New-Object system.security.AccessControl.FileSystemAccessRule($administratorsUserName,"Read","ContainerInherit,ObjectInherit","none","Allow")
$acl.AddAccessRule($accessrule)

# Set Modified ACL on administratorKeysFolder
Set-Acl -Path "$programdataPath\ssh\$administratorKeysFolder" -AclObject $acl
Write-Host "ACL of $programdataPath\ssh\$administratorKeysFolder has been updated to comply with OpenSSH required settings"

# Change Path to administrators_authorized_keys
$sshconfigfile = "$programdataPath\ssh\sshd_config"
$regex = '       AuthorizedKeysFile __PROGRAMDATA__/ssh/administrators_authorized_keys'
(Get-Content $sshconfigfile) -replace $regex, "       AuthorizedKeysFile __PROGRAMDATA__/ssh/$administratorKeysFolder/administrators_authorized_keys" | Set-Content $sshconfigfile
Write-Host "OpenSSH config has been adapted to use the following file for Administrators ssh keys$programdataPath\ssh\$administratorKeysFolder\administrators_authorized_keys"

# Restart SSHD
Restart-Service -Name sshd
Write-Host "OpenSSH Server has been restarted to load updated config"

cd $scriptDir