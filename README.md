# PowerMap
I got stuck on a Windows box, needed to do some quick recon, and nmap wasn't an option. So I wrote this.
PowerMap is basically nmap in PowerShell. Host discovery, port scanning, service detection - all the essentials. No external dependencies, just pure PowerShell.

Note that this thing is LOUD. 100 concurrent threads hammering ports will light up any decent EDR. 
I prioritized speed over stealth making it perfect for AUTHORIZED testing but terrible for staying under the radar.

If you need stealth, dial down the threads and increase timeouts. Or just use something else...

it'll handle 90% of your basic recon needs when you're stuck without proper tools, but it's missing the fancy nmap stuffs like OS detection, version scanning, scripts, stealth techniques etc...

## The features

- Host Discovery: Finds live hosts using ICMP ping and TCP probes
- Fast Port Scanning: Multi-threaded scanning for speed
- Service Detection: Identifies common services on open ports
- Flexible Target Support: Single IPs, CIDR ranges, IP ranges

## Usage 

```powershell
powerMap.ps1 <target(s)> [-Ports <ports>] [-Timeout <ms>] [-HostTimeout <ms>] [-MaxThreads <n>]
```

```powershell
# Scan a single host
.\powerMap.ps1 192.168.1.1

# Scan a network range
.\powerMap.ps1 192.168.1.0/24

# Scan specific ports
.\powerMap.ps1 mohamedg.me -Ports 80,443,22,21

# Fast scan with custom timeout
.\powerMap.ps1 192.168.1.1-50 -Timeout 50
```
# Bonus ++
If you need a simple single one liner command to perform port scanning on a host: use this command:
```powershell
echo "PORT    STATE"; port,port,port | % {$p=$_;try{$c=New-Object Net.Sockets.TcpClient;$c.Connect("Hosts IP",$p);"$p    OPEN"}catch{"$p    CLOSED/FILTRD"}}

# For example if i wanna scan 192.168.1.1 for common ports like 21,22,23,53,80,443,3389,8080
# I do it like this
echo "PORT    STATE"; 21,22,23,53,80,443,3389,8080 | % {$p=$_;try{$c=New-Object Net.Sockets.TcpClient;$c.Connect("192.168.1.1",$p);"$p    OPEN"}catch{"$p    CLOSED/FILTRD"}}
```
