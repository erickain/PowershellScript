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
