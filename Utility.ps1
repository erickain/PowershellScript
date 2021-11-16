#Install Sysmon Remotely

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
