$Text = "SeNetworkLogonRight"
Get-Content 'C:\Scripts\Brien.Log' | Select-String -Pattern $Text

Get-Content -Path 'C:\Program Files\Update Services\LogFiles\SoftwareDistribution.log' |Out-Host –Paging

Get-Content -Path C:\Windows\Logs\DISM\dism.log -Tail 50

#Because some services write continuously to a log file, you may want to display new lines as soon as they appear. 
#That's exactly the purpose of the -Wait parameter.
Get-Content -Path C:\Windows\WindowsUpdate.log -Tail 5 –Wait

#Displaying only specific lines
Select-String -Path C:\Windows\System32\LogFiles\Firewall\pfirewall.log ‑Pattern 'Drop' | Select-Object -Last 20


Select-String -Path C:\Windows\WindowsUpdate.log -Pattern 'error','warning'

#The following command searches for lines with the word "err" preceded and followed by a space. 
#It also displays the three lines before and after every match from the cluster log file.

Select-String C:\Windows\Cluster\Reports\Cluster.log -Pattern ' err ' ‑Context 3


Get-Content C:\Windows\debug\netlogon.log |Select-Object -First 30 -Skip 45

$weblog | Select-object -property c-ip

###  Parse Event log 
##https://www.sans.org/blog/working-with-the-event-log-part-3-accessing-message-elements/
#Using Convert-EventLogRecord allows us to easily use Get-WinEvent, taking the individual XML data elements in the Message property 
#and make them individually accessible on the pipeline
##L/DR: It makes the event log data much more easily accessible
#Install 
New-Item -ItemType Directory -Path C:\Tools -ErrorAction SilentlyContinue
Set-Location C:\Tools
Invoke-WebRequest -Uri https://raw.githubusercontent.com/jdhitsolutions/PSScriptTools/master/functions/Convert-EventLogRecord.ps1 -OutFile Convert-EventLogRecord.ps1
Set-ExecutionPolicy RemoteSigned -Force
Import-Module .\Convert-EventLogRecord.ps1

# Get the columns
Get-WinEvent -FilterHashtable @{ LogName="Security"; ID=4624 } -MaxEvents 1 | Convert-EventLogRecord |Get-Member
 
#Filter
Get-WinEvent -FilterHashtable @{ LogName="Security"; ID=4624 } -MaxEvents 1 | Convert-EventLogRecord | Select-Object -Property TargetUserName
Get-WinEvent -FilterHashTable @{LogName="Security";ID=4625;StartTime=((Get-Date).AddDays(-1));EndTime=(Get-Date)} | Convert-EventLogRecord | Select-Object -Property TargetUserName
Get-WinEvent -FilterHashtable @{ LogName="Security"; ID=4624 } | Convert-EventLogRecord | Where-Object -Property TargetUserName -NE 'SYSTEM' | Select-Object TargetUsername, TimeCreated, LogonType

#For better performance  Filter hash table first; Convert-EventLogRecord if you must
#https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/advanced-xml-filtering-in-the-windows-event-viewer/ba-p/399761
#https://github.com/jdhitsolutions/PSScriptTools





