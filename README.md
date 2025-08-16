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
