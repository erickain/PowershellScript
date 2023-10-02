# Pktmon usage

## **Add/Remove Filter:**

1. pktmon filter remove # Remove All Filters
2. pktmon filter list   # List all Filters
3. pktmon filter add -I 100.100.100.0/24 # Capture the traffic for Specified IP
4. pktmon filter add -p 53 -I 100.100.100.0/16 101.101.101.0/16 # filter IP and Port

## Start Realtime Capture:

pktmon start --etw --pkt-size 0 --comp 1

pktmon start -c --comp nics -m real-time # Capture Real time

## Stop Capture or Control C:

pktmon stop

## Convert etl to pcap for wireshark:

#Create Directory where you want to store pcap
mkdir C:\Temp1 # Create Directory where you want to store pcap

#Convert etltp log.pcapng for wireshark
pktmon etl2pcap C:\WINDOWS\system32\PktMon.etl -o C:\Temp1\log.pcapng 
