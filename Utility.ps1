#Install Sysmon Remotely

#Enable powershell remoting uisng psxec
 .\psexec.exe \\ComputerName -h -s powershell.exe Enable-PSRemoting -Force

$Session = New-PSSession -ComputerName <ComputerNane or IP> -Credential "Study\Administrator"

Copy-Item "C:\Users\Administrator\Desktop\Sysmon\*.*" -ToSession $Session -Destination C:\Windows\cpsysmon\  -Recurse

Invoke-Command -Session $session -ScriptBlock {cmd.exe /C "c:\windows\cpsysmon\Sysmon64.exe" -i -n -accepteula}
