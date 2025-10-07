#PowerMap v1.0

param(
    [Parameter(Mandatory=$true, Position=0)]
    [string[]]$Targets,

    [Parameter()]
    [int[]]$Ports,

    [Parameter()]
    [int]$Timeout = 100,

    [Parameter()]
    [int]$HostTimeout = 500,

    [Parameter()]
    [int]$MaxThreads = 100,

    [Parameter()]
    [switch]$Help
)

if ($Help) {
    Write-Host @"
PowerMap 1.1 - Ultra-Fast Port Scanner (Enhanced Edition)
Usage: .\PowerMap.ps1 <target(s)> [-Ports <ports>] [-Timeout <ms>] [-HostTimeout <ms>] [-MaxThreads <n>]
Examples:
  .\PowerMap.ps1 192.168.1.1
  .\PowerMap.ps1 192.168.1.0/24 -Ports 80,443,22
  .\PowerMap.ps1 scanme.nmap.org -Timeout 50
"@
    exit 0
}

# --- Console Output Functions ---
function Write-StatusOK {
    param([string]$Message)
    Write-Host "[" -NoNewline -ForegroundColor White
    Write-Host "+" -NoNewline -ForegroundColor Green
    Write-Host "] " -NoNewline -ForegroundColor White
    Write-Host $Message -ForegroundColor Green
}

function Write-StatusError {
    param([string]$Message)
    Write-Host "[" -NoNewline -ForegroundColor White
    Write-Host "x" -NoNewline -ForegroundColor Red
    Write-Host "] " -NoNewline -ForegroundColor White
    Write-Host $Message -ForegroundColor Red
}

function Write-StatusInfo {
    param([string]$Message)
    Write-Host "[" -NoNewline -ForegroundColor White
    Write-Host ">" -NoNewline -ForegroundColor Cyan
    Write-Host "] " -NoNewline -ForegroundColor White
    Write-Host $Message -ForegroundColor Cyan
}

function Write-StatusWarning {
    param([string]$Message)
    Write-Host "[" -NoNewline -ForegroundColor White
    Write-Host "!" -NoNewline -ForegroundColor Yellow
    Write-Host "] " -NoNewline -ForegroundColor White
    Write-Host $Message -ForegroundColor Yellow
}

function Write-NmapHeader {
    param([string]$Version, [string]$DateTime)
    Write-Host ""
    Write-Host "Starting PowerMap $Version ( https://github.com/mhdgning131/PowerMap ) at $DateTime" -ForegroundColor White
}

function Write-NmapScanReport {
    param([string]$Target, [string]$Hostname = $null)
    Write-Host ""
    if ($Hostname) {
        Write-Host "PowerMap scan report for " -NoNewline -ForegroundColor White
        Write-Host $Hostname -NoNewline -ForegroundColor Green
        Write-Host " (" -NoNewline -ForegroundColor White
        Write-Host $Target -NoNewline -ForegroundColor Green
        Write-Host ")" -ForegroundColor White
    } else {
        Write-Host "PowerMap scan report for " -NoNewline -ForegroundColor White
        Write-Host $Target -ForegroundColor Green
    }
}

function Write-HostStatus {
    param([string]$Latency, [string]$Method)
    Write-Host "Host is up (" -NoNewline -ForegroundColor White
    Write-Host "$Latency latency" -NoNewline -ForegroundColor Green
    Write-Host ")." -ForegroundColor White
}

function Write-PortHeader {
    Write-Host "PORT" -NoNewline -ForegroundColor White
    Write-Host "      " -NoNewline
    Write-Host "STATE" -NoNewline -ForegroundColor White
    Write-Host " " -NoNewline
    Write-Host "SERVICE" -ForegroundColor White
}

function Write-OpenPort {
    param([int]$Port, [string]$Service)
    $portStr = "$Port/tcp"
    Write-Host $portStr.PadRight(9) -NoNewline -ForegroundColor White
    Write-Host " " -NoNewline
    Write-Host "open" -NoNewline -ForegroundColor Green
    Write-Host "  " -NoNewline
    Write-Host $Service -ForegroundColor Yellow
}

function Write-ClosedPortsSummary {
    param([int]$ClosedCount, [int]$FilteredCount)
    if ($ClosedCount -gt 0 -and $FilteredCount -eq 0) {
        Write-Host "Not shown: " -NoNewline -ForegroundColor Gray
        Write-Host "$ClosedCount " -NoNewline -ForegroundColor White
        Write-Host "closed ports" -ForegroundColor Gray
    }
    elseif ($FilteredCount -gt 0 -and $ClosedCount -eq 0) {
        Write-Host "Not shown: " -NoNewline -ForegroundColor Gray
        Write-Host "$FilteredCount " -NoNewline -ForegroundColor White
        Write-Host "filtered ports" -ForegroundColor Gray
    }
    elseif ($ClosedCount -gt 0 -and $FilteredCount -gt 0) {
        Write-Host "Not shown: " -NoNewline -ForegroundColor Gray
        Write-Host "$ClosedCount " -NoNewline -ForegroundColor White
        Write-Host "closed ports, " -NoNewline -ForegroundColor Gray
        Write-Host "$FilteredCount " -NoNewline -ForegroundColor White
        Write-Host "filtered ports" -ForegroundColor Gray
    }
}

function Write-NmapFooter {
    param([int]$TotalScanned, [int]$HostsUp, [double]$Duration)
    Write-Host ""
    Write-Host "PowerMap done: " -NoNewline -ForegroundColor White
    Write-Host "$TotalScanned " -NoNewline -ForegroundColor Green
    Write-Host "IP address" -NoNewline -ForegroundColor White
    if ($TotalScanned -ne 1) { Write-Host "es" -NoNewline -ForegroundColor White }
    Write-Host " (" -NoNewline -ForegroundColor White
    Write-Host "$HostsUp " -NoNewline -ForegroundColor Green
    Write-Host "host" -NoNewline -ForegroundColor White
    if ($HostsUp -ne 1) { Write-Host "s" -NoNewline -ForegroundColor White }
    Write-Host " up) scanned in " -NoNewline -ForegroundColor White
    Write-Host "$([math]::Round($Duration,2)) " -NoNewline -ForegroundColor Green
    Write-Host "seconds" -ForegroundColor White
}

# --- Variables globales pour interruption ---
$Global:ScanInterrupted = $false

function Register-KeyboardInterrupt {
    try {
        [Console]::TreatControlCAsInput = $false
        [Console]::CancelKeyPress += {
            param($sender, $e)
            $e.Cancel = $true
            $Global:ScanInterrupted = $true
            Write-Host ""
            Write-StatusWarning "Scan interrupted by user. Cleaning up..."
        }
    } catch {
        Write-StatusWarning "Unable to register interrupt handler."
    }
}

function Test-ScanInterrupted {
    if ($Global:ScanInterrupted) {
        Write-Host ""
        Write-StatusWarning "Scan interrupted. Partial results displayed."
        return $true
    }
    return $false
}

# Top ports et mapping services
function Get-FastServices {
    $topPorts = @(
        20, 21, 22, 23, 25, 53, 67, 68, 69, 79, 80, 88, 106, 110, 111, 113, 119, 123, 135, 137, 138, 
        139, 143, 144, 161, 162, 179, 199, 264, 389, 427, 443, 445, 465, 500, 513, 514, 515, 548, 554, 
        587, 631, 636, 646, 873, 902, 989, 990, 993, 995, 1000, 1024, 1025, 1026, 1027, 1028, 1029, 1030, 
        1031, 1032, 1033, 1034, 1035, 1036, 1037, 1038, 1039, 1040, 1041, 1042, 1043, 1044, 1045, 1046, 
        1047, 1048, 1049, 1050, 1080, 1110, 1194, 1234, 1337, 1433, 1434, 1521, 1720, 1723, 1755, 1900, 
        1935, 2000, 2001, 2020, 2049, 2082, 2083, 2086, 2087, 2095, 2096, 2121, 2181, 2200, 2222, 2323, 
        2375, 2376, 2379, 2380, 2381, 2382, 2383, 2483, 2484, 2525, 2598, 2601, 2604, 2638, 2947, 2948, 
        2967, 3000, 3001, 3003, 3050, 3128, 3260, 3268, 3269, 3306, 3310, 3333, 3389, 3478, 3632, 3690, 
        3724, 3780, 3790, 4000, 4001, 4045, 4125, 4369, 4443, 4444, 4500, 4650, 4662, 4848, 4899, 5000, 
        5001, 5002, 5003, 5004, 5005, 5006, 5007, 5008, 5009, 5010, 5038, 5050, 5060, 5061, 5101, 5190, 
        5222, 5223, 5269, 5280, 5298, 5357, 5432, 5500, 5555, 5601, 5631, 5632, 5666, 5672, 5800, 5801, 
        5900, 5901, 5984, 5985, 5986, 6000, 6001, 6002, 6003, 6004, 6005, 6006, 6112, 6113, 6379, 6543, 
        6544, 6660, 6661, 6662, 6663, 6664, 6665, 6666, 6667, 6668, 6669, 6697, 6881, 6969, 7000, 7001, 
        7002, 7070, 7080, 7144, 7199, 7443, 7474, 7547, 7548, 7687, 7777, 8000, 8001, 8002, 8008, 8009, 
        8080, 8081, 8082, 8083, 8084, 8085, 8086, 8087, 8088, 8089, 8090, 8091, 8092, 8093, 8161, 8180, 
        8200, 8222, 8300, 8443, 8500, 8530, 8531, 8554, 8649, 8834, 8888, 8889, 9000, 9001, 9002, 9003, 
        9009, 9042, 9080, 9090, 9100, 9191, 9200, 9300, 9418, 9443, 9500, 9600, 9999, 10000, 10001, 10002, 
        10003, 10004, 10005, 10006, 10007, 10008, 10009, 10050, 10051, 10080, 10443, 11211, 11371, 12000, 
        13000, 15000, 16000, 17000, 18000, 19000, 20000, 25000, 25565, 26000, 27000, 27015, 27017, 27018, 
        27019, 28015, 28017, 32400, 32764, 49152, 49153, 49154, 50000, 50070, 50075, 50090, 54321
    )
    
    $services = @{
        20 = "ftp-data"; 21 = "ftp"; 22 = "ssh"; 23 = "telnet"; 25 = "smtp"; 53 = "domain"
        67 = "dhcp-server"; 68 = "dhcp-client"; 69 = "tftp"; 79 = "finger"; 80 = "http"
        88 = "kerberos"; 106 = "pop3pw"; 110 = "pop3"; 111 = "rpcbind"; 113 = "ident"
        119 = "nntp"; 123 = "ntp"; 135 = "msrpc"; 137 = "netbios-ns"; 138 = "netbios-dgm"
        139 = "netbios-ssn"; 143 = "imap"; 144 = "news"; 161 = "snmp"; 162 = "snmptrap"
        179 = "bgp"; 199 = "smux"; 264 = "bgmp"; 389 = "ldap"; 427 = "svrloc"
        443 = "https"; 445 = "microsoft-ds"; 465 = "smtps"; 500 = "isakmp"; 513 = "rlogin"
        514 = "syslog"; 515 = "printer"; 548 = "afp"; 554 = "rtsp"; 587 = "smtp-submission"
        631 = "ipp"; 636 = "ldaps"; 646 = "ldp"; 873 = "rsync"; 902 = "vmware-auth"
        989 = "ftps-data"; 990 = "ftps"; 993 = "imaps"; 995 = "pop3s"
        
        1000 = "cadlock"; 1024 = "kdm"; 1025 = "msrpc-alt"; 1026 = "lsass"; 1027 = "icq"
        1028 = "ms-lsa"; 1029 = "ms-lsa"; 1030 = "iad1"; 1031 = "iad2"; 1032 = "iad3"
        1033 = "netspy"; 1034 = "zincite-a"; 1035 = "multidropper"; 1036 = "nsstp"
        1037 = "ams"; 1038 = "mtqp"; 1039 = "sbl"; 1040 = "netarx"; 1041 = "danf-ak2"
        1042 = "afrog"; 1043 = "boinc-client"; 1044 = "dcutility"; 1045 = "fpitp"
        1046 = "wfremotertm"; 1047 = "neod1"; 1048 = "neod2"; 1049 = "td-postman"
        1050 = "java-or-otv"; 1080 = "socks"; 1110 = "nfsd-status"; 1194 = "openvpn"
        1234 = "hotline"; 1337 = "waste"; 1433 = "ms-sql-s"; 1434 = "ms-sql-m"
        1521 = "oracle"; 1720 = "h323q931"; 1723 = "pptp"; 1755 = "wms"; 1900 = "upnp"
        1935 = "rtmp"; 2000 = "cisco-sccp"; 2001 = "dc"; 2020 = "xinupageserver"
        2049 = "nfs"; 2082 = "cpanel"; 2083 = "cpanel-ssl"; 2086 = "whm"; 2087 = "whm-ssl"
        2095 = "webmail"; 2096 = "webmail-ssl"; 2121 = "ccproxy-ftp"; 2181 = "zookeeper"
        2200 = "ici"; 2222 = "EtherNetIP-1"; 2323 = "3d-nfsd"; 2375 = "docker"; 2376 = "docker-ssl"
        2379 = "etcd-client"; 2380 = "etcd-peer"; 2381 = "compaq-https"
        2382 = "ms-olap3"; 2383 = "ms-olap4"; 2483 = "oracle-db"; 2484 = "oracle-db-ssl"
        2525 = "ms-v-worlds"; 2598 = "citrix-rtmp"; 2601 = "zebra"; 2604 = "ospfd"
        2638 = "sybase"; 2947 = "gpsd"; 2948 = "wap-push"; 2967 = "symantec-av"
        3000 = "ppp"; 3001 = "nessus"; 3003 = "cgms"; 3050 = "gds-db"
        3128 = "squid-http"; 3260 = "iscsi"; 3268 = "ldap-global"; 3269 = "ldaps-global"
        3306 = "mysql"; 3310 = "dyna-access"; 3333 = "dec-notes"; 3389 = "rdp"
        3478 = "stun"; 3632 = "distcc"; 3690 = "svn"; 3724 = "world-of-warcraft"
        3780 = "dts"; 3790 = "lam"; 4000 = "terabase"; 4001 = "newoak"; 4045 = "lockd"
        4125 = "rww"; 4369 = "erlang-portmapper"; 4443 = "pharos"; 4444 = "krb524"
        4500 = "ipsec-nat-t"; 4650 = "ams"; 4662 = "edonkey"; 4848 = "appserv-http"
        4899 = "radmin"; 5000 = "upnp"; 5001 = "commplex-link"; 5002 = "rfe"
        5003 = "filemaker"; 5004 = "avt-profile-1"; 5005 = "avt-profile-2"
        5006 = "wsm-server"; 5007 = "wsm-server-ssl"; 5008 = "synaptics-lm"
        5009 = "winfs"; 5010 = "telelpathstart"; 5038 = "landesk-cba"
        5050 = "yahoo-im"; 5060 = "sip"; 5061 = "sips"; 5101 = "admdog"
        5190 = "aol-im"; 5222 = "xmpp-client"; 5223 = "xmpp-client-ssl"
        5269 = "xmpp-server"; 5280 = "xmpp-bosh"; 5298 = "presence"
        5357 = "wsdapi"; 5432 = "postgresql"; 5500 = "hotline"; 5555 = "freeciv"
        5601 = "kibana"; 5631 = "pcanywheredata"; 5632 = "pcanywherestat"
        5666 = "nrpe"; 5672 = "amqp"; 5800 = "vnc-http"; 5801 = "vnc-http-1"
        5900 = "vnc"; 5901 = "vnc-1"; 5984 = "couchdb"; 5985 = "wsman"
        5986 = "wsmans"; 6000 = "x11"; 6001 = "x11:1"; 6002 = "x11:2"
        6003 = "x11:3"; 6004 = "x11:4"; 6005 = "x11:5"; 6006 = "x11:6"
        6112 = "dtspc"; 6113 = "tproxy"; 6379 = "redis"; 6543 = "mythtv"
        6544 = "mythtv"; 6660 = "irc"; 6661 = "irc"; 6662 = "irc"; 6663 = "irc"
        6664 = "irc"; 6665 = "irc"; 6666 = "irc"; 6667 = "irc"; 6668 = "irc"
        6669 = "irc"; 6697 = "ircs-u"; 6881 = "bittorrent-tracker"
        6969 = "acmsoda"; 7000 = "afs3-fileserver"; 7001 = "afs3-callback"
        7002 = "afs3-prserver"; 7070 = "realserver"; 7080 = "empowerid"
        7144 = "portmap"; 7199 = "cassandra"; 7443 = "oracleas-https"
        7474 = "neo4j"; 7547 = "cwmp"; 7548 = "cwmp"; 7687 = "bolt"
        7777 = "cbt"; 8000 = "irdmi"; 8001 = "vcom-tunnel"; 8002 = "teradataordbms"
        8008 = "http"; 8009 = "ajp13"; 8080 = "http-proxy"; 8081 = "blackice-icecap"
        8082 = "blackice-alerts"; 8083 = "us-srv"; 8084 = "websnp"; 8085 = "unknown"
        8086 = "d-s-n"; 8087 = "simplifymedia"; 8088 = "radan-http"
        8089 = "unknown"; 8090 = "opsmessaging"; 8091 = "jamlink"
        8092 = "jetdirect"; 8093 = "unknown"; 8161 = "patrol-snmp"
        8180 = "unknown"; 8200 = "trivnet1"; 8222 = "vmware-fdm"
        8300 = "tmi"; 8443 = "pcsync-https"; 8500 = "fmtp"; 8530 = "wsus"
        8531 = "unknown"; 8554 = "rtsp-alt"; 8649 = "unknown"
        8834 = "unknown"; 8888 = "ddi-tcp-1"; 8889 = "ddi-tcp-2"
        9000 = "cslistener"; 9001 = "etlservicemgr"; 9002 = "dynamid"
        9003 = "ogs-client"; 9009 = "pichat"; 9042 = "unknown"
        9080 = "glrpc"; 9090 = "unknown"; 9100 = "jetdirect"
        9191 = "unknown"; 9200 = "wap-wsp"; 9300 = "vrace"
        9418 = "git"; 9443 = "tungsten-https"; 9500 = "ismserver"
        9600 = "unknown"; 9999 = "abyss"; 10000 = "snet-sensor-mgmt"
        10001 = "scp-config"; 10002 = "documentum"; 10003 = "documentum_s"
        10004 = "emcrmirccd"; 10005 = "emcrmird"; 10006 = "mysql-proxy"
        10007 = "mvs-capacity"; 10008 = "octopus"; 10009 = "swdtp-sv"
        10050 = "zabbix-agent"; 10051 = "zabbix-trapper"; 10080 = "amanda"
        10443 = "unknown"; 11211 = "memcache"; 11371 = "hkp"
        12000 = "cce4x"; 13000 = "unknown"; 15000 = "hydap"
        16000 = "fmsas"; 17000 = "unknown"; 18000 = "biimenu"
        19000 = "unknown"; 20000 = "dnp"; 25000 = "icl-twobase1"
        25565 = "minecraft"; 26000 = "quake"; 27000 = "flexlm0"
        27015 = "halflife"; 27017 = "mongod"; 27018 = "mongos"
        27019 = "mongodb"; 28015 = "unknown"; 28017 = "mongodb-web"
        32400 = "plex"; 32764 = "filenet-powertier"; 49152 = "unknown"
        49153 = "unknown"; 49154 = "unknown"; 50000 = "ibm-db2"
        50070 = "hadoop-namenode"; 50075 = "hadoop-datanode"
        50090 = "hadoop-secondarynn"; 54321 = "bo2k"
    }
    
    return @{ Services = $services; TopPorts = $topPorts }
}

function IPv4ToUInt32 {
    param([string]$ip)
    $bytes = ([System.Net.IPAddress]::Parse($ip)).GetAddressBytes()
    [Array]::Reverse($bytes)
    return [BitConverter]::ToUInt32($bytes, 0)
}

function UInt32ToIPv4 {
    param([uint32]$val)
    $bytes = [BitConverter]::GetBytes([uint32]$val)
    [Array]::Reverse($bytes)
    return ([System.Net.IPAddress]::new($bytes)).ToString()
}

function Expand-IPTargets {
    param([string[]]$InputTargets)

    $expandedTargets = @()

    foreach ($target in $InputTargets) {
        $t = $target.Trim()

        if ($t -match '^(?:\d{1,3}\.){3}\d{1,3}$') {
            $expandedTargets += $t
            continue
        }

        if ($t -match '^(\d{1,3}\.\d{1,3}\.\d{1,3})/?(\d{1,2})$') {
            $base = $matches[1]
            $cidr = [int]$matches[2]
            $t = "$base.0/$cidr"
        }

        if ($t -match '^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/(\d{1,2})$') {
            $network = $matches[1]
            $cidr = [int]$matches[2]
            if ($cidr -lt 0 -or $cidr -gt 32) { 
                Write-StatusWarning "Invalid CIDR: $t"
                continue 
            }

            try {
                $netUInt = IPv4ToUInt32 $network
                $hosts = [math]::Pow(2, (32 - $cidr))
                $hostCount = [int]($hosts - 2)
                if ($hostCount -lt 1) { $hostCount = [int]($hosts) }

                if ($hostCount -gt 1000) {
                    Write-StatusWarning "CIDR $t generates $hostCount hosts. Limited to first 1000 for performance."
                    $hostCount = 1000
                }

                $firstHost = $netUInt + 1
                for ($i = 0; $i -lt $hostCount; $i++) {
                    $expandedTargets += (UInt32ToIPv4 ($firstHost + $i))
                }
            } catch {
                Write-StatusError "Error expanding $t : $_"
            }
            continue
        }

        if ($t -match '^(\d{1,3}\.\d{1,3}\.\d{1,3}\.)?(\d{1,3})-(\d{1,3})$') {
            $base = $matches[1]
            if (-not $base) { 
                Write-StatusWarning "Missing base IP for range $t"
                continue 
            }
            $start = [int]$matches[2]
            $end = [int]$matches[3]
            for ($i = $start; $i -le $end; $i++) { $expandedTargets += "$base$i" }
            continue
        }

        $expandedTargets += $t
    }

    return $expandedTargets
}

function Test-HostAlive {
    param(
        [string[]]$Targets,
        [int]$TimeoutMs = 500,
        [int]$MaxThreads = 50
    )

    $runspacePool = [runspacefactory]::CreateRunspacePool(1, $MaxThreads)
    $runspacePool.Open()

    $scriptBlock = {
        param($target, $timeout)
        try {
            $ping = New-Object System.Net.NetworkInformation.Ping
            $reply = $ping.Send($target, [int]($timeout/2))
            if ($reply.Status -eq 'Success') {
                return @{ Target = $target; Alive = $true; Method = 'ICMP'; Latency = $reply.RoundtripTime }
            }
        } catch {}

        # Try TCP probes if ICMP fails
        $probePorts = @(80,443,22)
        foreach ($p in $probePorts) {
            try {
                $sock = New-Object Net.Sockets.TcpClient
                $async = $sock.BeginConnect($target,$p,$null,$null)
                $ok = $async.AsyncWaitHandle.WaitOne([int]($timeout/4))
                if ($ok -and $sock.Connected) { 
                    $sock.EndConnect($async)
                    $sock.Close()
                    return @{ Target=$target; Alive=$true; Method="TCP:$p"; Latency=0 }
                }
                $sock.Close()
            } catch {}
        }
        return @{ Target = $target; Alive = $false; Method = 'None'; Latency = 0 }
    }

    $jobs = @()
    foreach ($t in $Targets) {
        $ps = [powershell]::Create().AddScript($scriptBlock).AddArgument($t).AddArgument($TimeoutMs)
        $ps.RunspacePool = $runspacePool
        $jobs += @{ PowerShell = $ps; Handle = $ps.BeginInvoke(); Target = $t }
    }

    $alive = @()
    foreach ($job in $jobs) {
        if ($Global:ScanInterrupted) { break }
        try {
            $res = $job.PowerShell.EndInvoke($job.Handle)
            if ($res.Alive) { 
                $alive += $res 
            }
        } catch {}
        $job.PowerShell.Dispose()
    }

    $runspacePool.Close()
    $runspacePool.Dispose()
    
    $uniqueAlive = @{}
    foreach ($alivehost in $alive) {
        if (-not $uniqueAlive.ContainsKey($alivehost.Target)) {
            $uniqueAlive[$alivehost.Target] = $alivehost
        }
    }
    
    return $uniqueAlive.Values
}

function Invoke-FastPortScan {
    param(
        [string]$Target,
        [int[]]$Ports,
        [int]$TimeoutMs,
        [int]$MaxThreads = 50
    )

    $runspacePool = [runspacefactory]::CreateRunspacePool(1, $MaxThreads)
    $runspacePool.Open()

    $script = {
        param($target, $port, $timeout)
        try {
            $c = New-Object Net.Sockets.TcpClient
            $async = $c.BeginConnect($target,$port,$null,$null)
            $connected = $async.AsyncWaitHandle.WaitOne($timeout)
            if ($connected -and $c.Connected) { 
                $c.EndConnect($async)
                $c.Close()
                return @{ Port=$port; State='open' }
            }
            $c.Close()
            return @{ Port=$port; State='closed' }
        } catch { 
            return @{ Port=$port; State='filtered' }
        }
    }

    $jobs = @()
    foreach ($p in $Ports) {
        $ps = [powershell]::Create().AddScript($script).AddArgument($Target).AddArgument($p).AddArgument($TimeoutMs)
        $ps.RunspacePool = $runspacePool
        $jobs += @{ PowerShell = $ps; Handle = $ps.BeginInvoke(); Port = $p }
    }

    $results = @()
    foreach ($job in $jobs) {
        if ($Global:ScanInterrupted) { break }
        try {
            $r = $job.PowerShell.EndInvoke($job.Handle)
            $results += $r
        } catch { 
            $results += @{ Port = $job.Port; State = 'filtered' }
        }
        $job.PowerShell.Dispose()
    }

    $runspacePool.Close()
    $runspacePool.Dispose()
    return $results
}

# -------------------- Main --------------------

# Initialize
function Register-KeyboardInterrupt {
    try {
        [Console]::TreatControlCAsInput = $false
        [Console]::CancelKeyPress += {
            param($sender, $e)
            $e.Cancel = $true
            $Global:ScanInterrupted = $true
            Write-Host ""
            Write-StatusWarning "Scan interrupted by user. Cleaning up..."
        }
    } catch {}
}
$services = Get-FastServices
if (-not $Ports) { $Ports = $services.TopPorts }

Write-NmapHeader -Version "1.1" -DateTime (Get-Date -Format 'yyyy-MM-dd HH:mm')

$expandedTargets = Expand-IPTargets -InputTargets $Targets
if ($expandedTargets.Count -eq 0) { 
    Write-StatusError "No valid targets found"
    exit 1 
}

$startTime = Get-Date

if ($expandedTargets.Count -gt 1) { 
    Write-StatusInfo "PowerMap scan initiating for $($expandedTargets.Count) targets"
}

$aliveHosts = Test-HostAlive -Targets $expandedTargets -TimeoutMs $HostTimeout -MaxThreads $MaxThreads

if (Test-ScanInterrupted) { exit 1 }

if ($aliveHosts.Count -eq 0) {
    Write-StatusError "All hosts appear to be down or filtered"
    Write-Host ""
    Write-Host "Note: Host seems down. If it is really up, but blocking our ping probes," -ForegroundColor Gray
    Write-Host "try -Pn next time to skip the host discovery phase." -ForegroundColor Gray
    Write-NmapFooter -TotalScanned $expandedTargets.Count -HostsUp 0 -Duration ((Get-Date) - $startTime).TotalSeconds
    exit 0
}

$totalHosts = $aliveHosts.Count
$scannedHosts = 0

foreach ($h in $aliveHosts) {
    if (Test-ScanInterrupted) { break }
    
    $target = $h.Target
    $scannedHosts++
    
    if ($totalHosts -gt 1) { 
        Write-Progress -Activity "PowerMap Port Scanning" -Status "Scanning $target ($scannedHosts/$totalHosts)" -PercentComplete (($scannedHosts / $totalHosts) * 100) 
    }

    $portResults = Invoke-FastPortScan -Target $target -Ports $Ports -TimeoutMs $Timeout -MaxThreads $MaxThreads
    $openPorts = $portResults | Where-Object { $_.State -eq 'open' } | Sort-Object Port
    $closedPorts = $portResults | Where-Object { $_.State -ne 'open' }

    $hostname = $null
    try {
        $job = [System.Net.Dns]::BeginGetHostEntry($target,$null,$null)
        if ($job.AsyncWaitHandle.WaitOne(200)) { 
            $entry = [System.Net.Dns]::EndGetHostEntry($job)
            if ($entry.HostName -ne $target) { 
                $hostname = $entry.HostName 
            }
        }
    } catch {}

    # Display results
    Write-NmapScanReport -Target $target -Hostname $hostname
    
    $lat = if ($h.Latency -lt 1000) { "$($h.Latency)ms" } else { "$([math]::Round($h.Latency/1000,3))s" }
    Write-HostStatus -Latency $lat -Method $h.Method

    if ($openPorts.Count -eq 0) { 
        Write-Host "All $($Ports.Count) scanned ports on " -NoNewline -ForegroundColor Gray
        Write-Host $target -NoNewline -ForegroundColor White
        Write-Host " are " -NoNewline -ForegroundColor Gray
        Write-Host "closed" -ForegroundColor Red
    }
    else {
        # Show closed/filtered ports summary
        if ($closedPorts.Count -gt 0) {
            $closedCount = ($closedPorts | Where-Object { $_.State -eq 'closed' }).Count
            $filteredCount = ($closedPorts | Where-Object { $_.State -eq 'filtered' }).Count
            Write-ClosedPortsSummary -ClosedCount $closedCount -FilteredCount $filteredCount
        }
        
        Write-PortHeader
        foreach ($p in $openPorts) {
            $svc = if ($services.Services.ContainsKey($p.Port)) { 
                $services.Services[$p.Port] 
            } else { 
                'unknown' 
            }
            Write-OpenPort -Port $p.Port -Service $svc
        }
    }

    if ($totalHosts -gt 1 -and $scannedHosts -lt $totalHosts) { 
        Write-Host ""
    }
}

if ($totalHosts -gt 1) { 
    Write-Progress -Activity "PowerMap Port Scanning" -Completed 
}

$endTime = Get-Date
$duration = ($endTime - $startTime).TotalSeconds
$totalScanned = $expandedTargets.Count
$actualHostsUp = $aliveHosts.Count


Write-NmapFooter -TotalScanned $totalScanned -HostsUp $actualHostsUp -Duration $duration

