#Follow TXT file with PowerShell OGV(out-gridview) command
get-content [path\to\textfile.txt] -wait | ogv
# Get public IP of the server
nslookup myip.opendns.com resolver1.opendns.com 
Resolve-DnsName -Name myip.opendns.com -Server resolver1.opendns.com

#Force deletion of an AD account which has leaf Object
   # 1 - force inheritance 
$users = Get-ADUser -ldapfilter “(objectclass=user)” -searchbase “ou=companyusers,dc=enterpriseit,dc=co”
ForEach($user in $users)
{
    # Binding the users to DS
    $ou = [ADSI](“LDAP://” + $user)
    $sec = $ou.psbase.objectSecurity
 
    if ($sec.get_AreAccessRulesProtected())
    {
        $isProtected = $false ## allows inheritance
        $preserveInheritance = $true ## preserver inhreited rules
        $sec.SetAccessRuleProtection($isProtected, $preserveInheritance)
        $ou.psbase.commitchanges()
        Write-Host “$user is now inherting permissions”;https://github.com/erickain/PowershellScript/blob/main/Utility.ps1
    }
    else
    {
        Write-Host “$User Inheritable Permission already set”
    }
}
    # 2 - Delete object and leaf object
Remove-ADobject (Get-ADUser olduser).distinguishedname -Recursive -Confirm:$false


Get a list of all non-Windows servers that have not contacted Active Directory in the last 30 days

Get-ADComputer -Filter { OperatingSystem -notlike "Windows Server*" } -Properties PasswordLastSet | ? { (((Get-Date) – $_.PasswordLastSet).Days) -gt 30} | Select Name, @{N="Age";E={ (((Get-Date) – $_.PasswordLastSet).Days) }}

# send text message https://www.alexcomputerbubble.com/use-powershell-to-send-a-text-message-sms/

# Port Scanner 
0..65535 | Foreach-Object { Test-NetConnection -Port $_ scanme.nmap.org -WA SilentlyContinue | Format-Table -Property ComputerName,RemoteAddress,RemotePort,TcpTestSucceeded }

# Download psexec.exe
Invoke-WebRequest -uri https://live.sysinternals.com/psexec.exe -OutFile .\psexec.exe

# Enable rdp remotely on english OS
Invoke-Command -ComputerName $t -ScriptBlock {
    Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name "fDenyTSConnections" -Value 0; `
    Enable-NetFirewallRule -DisplayGroup "Remote Desktop"`
    # Disable Network Level Authentication (NLA) on the remote computer`
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -Value 0
}

#Install Sysmon Remotely

# run poweershell command remotely withoug powershell remoting 
.\psexec.exe \\ComputerName powershell  "Powershell_command"

#Enable powershell remoting uisng psxec
 .\psexec.exe \\ComputerName -h -s powershell.exe Enable-PSRemoting -Force

$Session = New-PSSession -ComputerName <ComputerNane or IP> -Credential "Study\Administrator"

Copy-Item "C:\Users\Administrator\Desktop\Sysmon\*.*" -ToSession $Session -Destination C:\Windows\cpsysmon\  -Recurse

Invoke-Command -Session $session -ScriptBlock {cmd.exe /C "c:\windows\cpsysmon\Sysmon64.exe" -i -n -accepteula}




@echo off
Psexec.exe -sd \\%1 procmon -accepteula -backingfile c:\temp\proc.pml -quiet
Pause
Psexec.exe -sd \\%1 procmon -accepteula -terminate -quiet
Xcopy \\%1\c$\temp\proc.pml c:\temp\
Del \\%1\c$\temp\proc.pml
Procmon.exe /openlog c:\temp\proc.pm


# Backup Event Log
(Get-WmiObject -Class Win32_NTEventlogFile | Where-Object LogfileName -EQ 'System').BackupEventlog('C:\Temp\System.evtx')
(Get-WmiObject -Class Win32_NTEventlogFile | Where-Object LogfileName -EQ 'Application').BackupEventlog('C:\Temp\Application.evtx')

# Navigate the windows event log tree
WEVTUtil query-events "Microsoft-Windows-GroupPolicy/Operational" /format:xml /e:sysmonview > eventlog.xml

#SMB1
Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol #Detect
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol  #Disable
Enable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol  #Enable

# Get server uptime
(get-date) - (gcim Win32_OperatingSystem).LastBootUpTime  
Get-Uptime -Since

    #Renew  cert of the RDS WebClient
Install-RDWebClientPackage
Import-RDWebClientBrokerCert <.cer path file path base64 or not> 

    #Optionally, you can publish the client for testing before official release by running this cmdlet
Publish-RDWebClientPackage -Type Test -Latest

Publish-RDWebClientPackage -Type Production -Latest

#Enable TLS 1.2  support
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12

# Get your PUblic IP 
(Invoke-RestMethod ipinfo.io/json).ip

#Get Powershell version
Get-Host | Select Version

#Send email 
Send-MailMessage -From 'bob@outlook.com' -To 'sam@outlook.com', 'john@outlook.com' -Subject 'Bob CV' -Body 'Here is my CV' -Attachments .\cv.pdf -Priority High -DeliveryNotificationOption OnSuccess, OnFailure -SmtpServer 'smtp-mail.outlook.com' -port 587 -UseSsl
$sendMailParams = @{
    From = 'adbertram@gmail.com' ## Must be gmail.com
    To = 'someemail@domain.com'
    Subject = 'some subject'
    Body = 'some body'
    SMTPServer = 'smtp.gmail.com'
    SMTPPort = 587
    UseSsl = $true
    Credential = $gmailCred
}
Send-MailMessage @sendMailParams


#Query stopped services setup as auto 
$computer = (Get-Item env:\Computername).Value
#Start all non-running Auto services
Get-WmiObject win32_service -ComputerName $computer -Filter "startmode = 'auto' AND state != 'running'"


- WIndows Activation
$computer = gc env:computername
$key = "aaaaa-bbbbb-ccccc-ddddd-eeeee"
$service = get-wmiObject -query "select * from SoftwareLicensingService" -computername $computer
$service.InstallProductKey($key)
$service.RefreshLicenseStatus()


# Start all Automatic Services that are currently stopped or not running using PowerShell
$computer = (Get-Item env:\Computername).Value
#Start all non-running Auto services
Get-WmiObject win32_service -ComputerName $computer -Filter "startmode = 'auto' AND state != 'running' AND name != 'sppsvc'" | Invoke-WmiMethod -Name StartService

#Output any services still not running
$stoppedServices = Get-WmiObject win32_service -ComputerName $computer -Filter "startmode = 'auto' AND state != 'running' AND name != 'sppsvc'" | select -expand Name
Write-Host "$env:ComputerName : Stopped Services: $stoppedServices"

# Change power mode 
$p = Get-CimInstance -Name root\cimv2\power -Class win32_PowerPlan -Filter "ElementName = 'High Performance'"      
powercfg /setactive ([string]$p.InstanceID).Replace("Microsoft:PowerPlan\{","").Replace("}","")

### Manage  HyperV VM snapshot
#Take Snapshot/Checkpoint
Checkpoint-VM -Name Test -SnapshotName BeforeInstallingUpdates

# Delete Snapshot
Get-VM TestVM | Remove-VMSnapshot -Name Experiment*

#List Snapshot 
Get-VMSnapshot -VMName TestVM


######## Manage AD  User password #########
# Change a specified user's password
Set-ADAccountPassword -Identity elisada -OldPassword (ConvertTo-SecureString -AsPlainText "p@ssw0rd" -Force) -NewPassword (ConvertTo-SecureString -AsPlainText "qwert@12345" -Force)

# Set a password for a user account using a distinguished name
Set-ADAccountPassword -Identity 'CN=Elisa Daugherty,OU=Accounts,DC=Fabrikam,DC=com' -Reset -NewPassword (ConvertTo-SecureString -AsPlainText "p@ssw0rd" -Force)

# Change password at log on
Set-ADUser -Identity worker03 -ChangePasswordAtLogon $true
