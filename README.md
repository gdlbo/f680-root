# F680 Jailbreak

Root shell on a ZTE ZXHN F680 (MGTS firmware `V9.1.10P1N9`) without opening the
case.

Run a file with no arguments and it prints the same help on all three:

```text
f680-root.sh - root shell on a ZTE ZXHN F680 (MGTS V9.1.10P1N9)
            via the hidden /webFac factory mode

usage: f680-root.sh [mode] [options]

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
  f680-root.sh -shell
  f680-root.sh -status
  f680-root.sh -exec "displayDB DevInfo"
  f680-root.sh -ip 192.168.1.1 -u mgts -p mtsoao -creds

notes:
  one dash or two, same thing: -status == --status
  credentials rotate on every run; the previous password stops working
  telnetd survives reboots, so after a restart just re-run
  telnet allows two sessions; a closed one holds its slot for 300 seconds
```

```bash
./f680-root.sh -shell           # bash, Linux / macOS / Git Bash
```

```powershell
.\f680-root.ps1 -shell          # Windows PowerShell 5.1+
```

```bash
./f680-root.py -shell           # python 3, stdlib only - has the extra modes
```

A run looks like this:

```text
[1] reset              -> 400
[2] SendSq rand=16     -> 200 (protocol v1)
[4] CheckLoginAuth     -> 200
[5] FactoryMode mode=2 -> 200
host: 192.168.1.1
user: Xx000000
pass: Yy111111
telnet 192.168.1.1
Credentials rotate on each run. Telnetd stays enabled across reboots.

  ZTE F680 shell - 'exit' to leave. Credentials rotate every run.

BusyBox v1.17.2 (2021-11-17 10:20:19 CST) built-in shell (ash)
/ # cat /proc/uptime
12345.67 89012.34
/ #
```

## How it works

The router's web UI ships a hidden factory-mode CGI under `/webFac`. It speaks a
five-step handshake:

1. `POST /webFac` `SendSq.gch` → `400 bad syntax` (resets the CGI)
2. `POST /webFac` `RequestFactoryMode.gch` → the device drops the socket
3. `POST /webFac` `SendSq.gch?rand=N\r\n` → empty body means protocol v1, key slot
   `N`; a `newrand=N` body means v2, slot `((0x1000193*rand)&0x3F ^ newrand) % 60`
4. Encrypt `CheckLoginAuth.gch?version50&user=..&pass=..` and POST it to
   `/webFacEntry`
5. Encrypt `FactoryMode.gch?mode=2&user=notused` → the reply contains
   `FactoryModeAuth.gch?user=..&pass=..`, fresh telnet credentials

The key is 24 bytes cut from a static table and XORed with `0xA5`, which makes it
AES-192-ECB. No padding is added by the device, so plaintext is zero-padded to a
16-byte boundary.

`mode=2` starts telnetd on port 23. Nothing else is modified — no config is
written, no firmware is touched.

## Options

All three scripts take the same flags and all print the same help when run
without arguments. In bash and python one dash or two is the same thing
(`-status` == `--status`); PowerShell uses its own `-Status` spelling.

| Flag | Meaning | sh | ps1 | py |
| --- | --- | :-: | :-: | :-: |
| *(no flag)* | Print help | yes | yes | yes |
| `-shell` | Get access, then open the console | yes | yes | yes |
| `-creds` | Print telnet credentials only | yes | yes | yes |
| `-check` | Probe whether `/webFac` exists | yes | yes | yes |
| `-status` | Health report over telnet, read-only | raw | yes | yes |
| `-exec "cmd"` | Run one command on the router | yes | yes | yes |
| `-config [DIR]` | Download log and config into `DIR` | no | no | yes |
| `-menu` | Interactive menu for provider-link and tuning changes | no | no | yes |
| `-dry-run` | With `-menu`: print commands instead of writing them | no | no | yes |
| `-ip <addr>` | Router address (default `192.168.1.1`) | yes | yes | yes |
| `-port <n>` | Web port (default `80`) | yes | yes | yes |
| `-u, -user <name>` | Web login (default `mgts`) | yes | yes | yes |
| `-p, -pass <pw>` | Web password (default `mtsoao`) | yes | yes | yes |
| `-quiet` | Print only the result | yes | yes | yes |
| `-rand <0-59>` | Pin the key slot instead of picking one | no | yes | yes |

`-status` in the shell version collects the same `/proc` and `displayDB` output
but prints it raw instead of formatting a report; `f680-root.ps1 -Status` and
`f680-root.py -status` render the formatted version shown below.

## Status report

`--status` opens one telnet session and reads `/proc` plus the config database.
It never writes anything.
```text
F680 status
  model           F680
  firmware        V9.1.10P1N9  (2021-11-17 11:08:58)
  serial          ******
  uptime          1d 18h 13m

CPU / memory
  cpu             9.1%  0.5%
  load            0.10 0.12 0.09
  memory          368608 of 469720 kB free (22% used)

WAN
  address         100.64.12.34  mask 255.255.0.0
  gateway         100.64.0.1
  mac             aa:bb:cc:dd:ee:ff
  rx / tx         11887873 / 11450990 packets
  errors          rx 0 drop 0 / tx 0 drop 0

Conntrack
  entries         586 / 29344 (1%)

Remote management (TR-069)
  acs             http://acs.example.net:7547
  enabled         yes, periodic inform every 604800 s
  upgrades        managed by ACS: 0

Telnet
  enabled         yes, port 23, max 2 sessions
  watchdog        clock:3906250 heartbeat:20 wdt_state:1

LAN leases (2)
  192.168.1.20    11:22:33:44:55:66  laptop
  192.168.1.21    aa:bb:cc:dd:ee:ff  desktop

Address conflicts
  [!] 192.168.1.20 is leased to 11:22:33:44:55:66 but answers as aa:bb:cc:dd:ee:ff

Bridge ports (learned MACs)
  port 2: 5  port 3: 12
```

**`uptime` proves whether the box rebooted** — if the web UI is dead but uptime
keeps growing, nothing crashed. **`Address conflicts`** cross-checks the DHCP
leases against `/proc/net/arp`, which catches a device holding a lease for one
address while another answers on it. Every value in the sample above is made up.

## Interactive menu

`--menu` covers the changes that touch the provider link. Every action asks for
`yes` first, and `--dry-run` prints the commands without running them.

```text
 1) show status
 2) show TR-069 settings
 3) detach from the provider: turn ACS / TR-069 off
 4) re-attach: TR-069 on, inform every 12 h
 5) apply the stability tuning
 6) roll the stability tuning back
 7) enable or disable telnet
 8) download log and config
 0) exit
```

Option 3 sets `MgtServer.Tr069Enable=0` and `PeriodicInformEnable=0`, then
`sendcmd 1 DB save`. The ISP loses remote access until option 4 puts it back.
Option 6 restores the firmware defaults of the four tuning fields (`-1`, `1`,
`1`, `42344`).

## Things that will bite you

**Credentials rotate.** Every run issues a new telnet user/password and the old
one stops working immediately. That is not a bug — the firmware generates them
per `mode=2` request. Telnetd itself stays enabled across reboots
(`TelnetCfg: TS_Enable=1, Lan_Enable=1, Lan_EnableAfterOlt=1`), so after a reboot
you only need to re-run this script to get a fresh password, not to re-enable
anything.

**Two sessions max.** `TelnetCfg.Max_Con_Num=2` and a closed session keeps its
slot for `ExitTime=300` seconds. Both scripts therefore connect exactly once and
never probe the port first — probing costs you a slot and the real login fails
with `The connect number is limited`. If you hit that, close your other telnet
windows and wait.

**The shell is jailed.** BusyBox 1.17.2 ash with `PATH=/sbin:/bin:/usr/sbin:/usr/bin`.
`id`, `uname`, `head`, `tail`, `strings`, `dmesg`, `sort`, `tr` are all missing.
Useful commands that do exist: `sendcmd`, `displayDB`, `switchtst`, `brctl`,
`iptables`, `iwconfig`, `tcpdump`, `cat /proc/...`.

**Reading and writing config.** `sendcmd 1 DB p <Table>` reads a table,
`sendcmd 1 DB set <Table> <row> <Field> <Value>` writes one, and
`sendcmd 1 DB save` commits. `displayDB <Table>` is a read-only alternative. Table
names drop the `OBJ_` prefix and `_ID` suffix, so `OBJ_DHCP4S_POOL_ID` becomes
`DHCP4sPool`. Writing without `save` is lost on reboot; writing *with* `save` is
not undoable except by hand, so read before you write.

**The web server is fragile.** The CMAPI (`/?_type=menuData&_tag=...`) serves one
request per session and stops accepting TCP for up to a minute if you hammer it.
This tool does not use the CMAPI, so it is unaffected — but if the web UI seems
dead while ping still answers, the box is fine and only `httpd` is wedged.

**There is no autostart.** `/etc/rcS.d` sits on read-only jffs2, and the only
writable hook `rcS` reads is `/userconfig/ttyredir.cfg`, which accepts a single
digit and nothing else. Editing `rcS` means remounting the root filesystem
read-write with no rollback — recovery is the reset button. Re-running the script
takes two seconds, so don't.

## Prior art

The protocol was reverse-engineered by
[douniwan5788/zte_modem_tools](https://github.com/douniwan5788/zte_modem_tools)