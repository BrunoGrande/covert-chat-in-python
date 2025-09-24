#!/usr/bin/env python3
"""
Covert ICMP Chat (Type 0 Echo Reply) —  for Docker with static IPs.
- 2-byte stego header at payload start: [2 bits ctrl | 6 bits seq | 8 bits data]
- Handshake: START+MAGIC (0xB7) then START+NONCE (1B). Higher nonce -> master.
- Data: stdin bytes sent as MID frames; END on EOF/Ctrl-C.
Assumptions (valid on Docker bridge):
- Peer is passed as a literal IPv4 (10.0.0.10/11). No DNS retries.
- IPv4 header has no options => IHL = 20 bytes.
"""

import argparse, os, random, select, socket, struct, sys, threading, time
from typing import Optional, Tuple

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

ICMP_ECHO_REPLY: int = 0  # Type 0
ICMP_CODE: int = 0

CTRL_START: int = 0b00
CTRL_MID:   int = 0b01
CTRL_IDLE:  int = 0b10  # reserved (optional keepalive)
CTRL_END:   int = 0b11

MAGIC: int = 0xB7
MAX_SEQ: int = 64

SEND_INTERVAL: float = 0.08       # spacing between data packets
HANDSHAKE_INTERVAL: float = 0.50  # spacing during handshake
RECV_TIMEOUT: float = 0.20        # socket receive timeout (seconds)

PAD_LEN: int = 14  # extra payload size to look less uniform


# ---- stego header: [2b ctrl | 6b seq | 8b data] ----
def pack_header(ctrl: int, seq: int, data: int) -> bytes:
    return bytes([((ctrl & 3) << 6) | (seq & 63), data & 0xFF])

def unpack_header(b: bytes) -> Tuple[int,int,int]:
    x = b[0]
    return (x >> 6) & 3, x & 63, b[1]

# ---- checksum + icmp builder ----
def icmp_checksum(data: bytes) -> int:
    if len(data) & 1:
        data += b"\x00"
    s = 0
    for i in range(0, len(data), 2):
        s += int.from_bytes(data[i:i+2], "big")
    s = (s & 0xFFFF) + (s >> 16)
    s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF

def build_icmp_echo_reply(identifier: int, sequence: int, payload: bytes) -> bytes:
    hdr = struct.pack("!BBHHH", ICMP_ECHO_REPLY, ICMP_CODE, 0, identifier, sequence)
    chk = icmp_checksum(hdr + payload)
    return struct.pack("!BBHHH", ICMP_ECHO_REPLY, ICMP_CODE, chk, identifier, sequence) + payload

def build_payload(ctrl: int, seq: int, data_byte: int) -> bytes:
    stego = pack_header(ctrl, seq, data_byte)
    pad = struct.pack("!IH", int(time.time()), os.getpid() & 0xFFFF)
    return stego + pad + os.urandom(max(0, PAD_LEN - len(pad)))

# ---- peer ----
class Peer:
    def __init__(self, peer_ip: str, verbose: bool):
        self.peer_ip = peer_ip               # literal IPv4 (10.0.0.10/11)
        self.verbose = verbose
        # single raw ICMP socket for both send/recv (Linux)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        self.sock.settimeout(RECV_TIMEOUT)

        self.identifier = os.getpid() & 0xFFFF
        self.send_seq = 0
        self.role: Optional[str] = None
        self.nonce = random.randint(0, 255)
        self.peer_nonce: Optional[int] = None
        self.handshaked = False

        self.input_queue: list[int] = []
        self.lock = threading.Lock()
        self.stop = threading.Event()

    def log(self, *a):
        if self.verbose: print(*a, flush=True)

    def next_seq(self) -> int:
        v = self.send_seq
        self.send_seq = (self.send_seq + 1) % MAX_SEQ
        return v

    def send_frame(self, ctrl: int, data_byte: int):
        seq = self.next_seq()
        pkt = build_icmp_echo_reply(self.identifier, seq, build_payload(ctrl, seq, data_byte))
        try:
            self.sock.sendto(pkt, (self.peer_ip, 0))
        except Exception as e:
            self.log("[send error]", e)

    # ---- threads ----
    def receiver(self):
        while not self.stop.is_set():
            try:
                pkt, _ = self.sock.recvfrom(65535)
            except socket.timeout:
                continue
            except Exception as e:
                self.log("[recv error]", e); continue

            # Assume standard IPv4 header without options in Docker => IHL=20
            if len(pkt) < 28:  # 20 (IP) + 8 (ICMP)
                continue

            ihl = 20
            icmp_hdr = pkt[ihl:ihl+8]
            icmp_type, code, chk, ident, seq = struct.unpack("!BBHHH", icmp_hdr)
            if icmp_type != ICMP_ECHO_REPLY:
                continue
            payload = pkt[ihl+8:]
            if len(payload) < 2:
                continue

            # Optional: filter by source IP equals peer_ip
            src_ip = socket.inet_ntoa(pkt[12:16])
            if src_ip != self.peer_ip:
                continue

            ctrl, sseq, data = unpack_header(payload[:2])

            # Handshake
            if not self.handshaked:
                if ctrl == CTRL_START and data == MAGIC:
                    self.log("[hs] peer MAGIC")
                elif ctrl == CTRL_START:
                    self.peer_nonce = data
                    if self.nonce > self.peer_nonce:
                        self.role = "master"
                    elif self.nonce < self.peer_nonce:
                        self.role = "slave"
                    else:
                        self.role = "master" if self.identifier > ident else "slave"
                    self.handshaked = True
                    print(f"[+] role: {self.role}", flush=True)
                continue

            # Data
            if ctrl == CTRL_MID:
                sys.stdout.write(chr(data)); sys.stdout.flush()
            elif ctrl == CTRL_END:
                print("\n[+] peer ended.", flush=True)
                self.stop.set(); break

    def stdin_reader(self):
        while not self.stop.is_set():
            r,_,_ = select.select([sys.stdin], [], [], 0.1)
            if sys.stdin in r:
                chunk = os.read(sys.stdin.fileno(), 1024)
                if not chunk:
                    self.stop.set(); break
                with self.lock: self.input_queue += list(chunk)
            else:
                time.sleep(0.05)

    def sender(self):
        # Handshake phase
        last = 0.0; sent_magic = False
        while not self.stop.is_set() and not self.handshaked:
            now = time.time()
            if (not sent_magic) or (now - last) > HANDSHAKE_INTERVAL:
                self.send_frame(CTRL_START, MAGIC); sent_magic = True; last = now
                time.sleep(HANDSHAKE_INTERVAL/2); self.send_frame(CTRL_START, self.nonce)
            time.sleep(0.1)
        if not self.handshaked: return

        # Data phase
        while not self.stop.is_set():
            b = None
            with self.lock:
                if self.input_queue:
                    b = self.input_queue.pop(0)
            if b is not None:
                self.send_frame(CTRL_MID, b); time.sleep(SEND_INTERVAL)
            else:
                time.sleep(0.02)

    def end(self):
        try: self.send_frame(CTRL_END, 0)
        except: pass

def main():
    ap = argparse.ArgumentParser(description="Covert ICMP chat (Type 0) — Docker/static IPs")
    ap.add_argument("--peer", required=True, help="Peer IPv4 (e.g., 10.0.0.10/11)")
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()

    peer = Peer(args.peer, args.verbose)
    print("[*] Covert ICMP chat. Type and press Enter. Ctrl-D to end.", flush=True)

    th = [
        threading.Thread(target=peer.receiver, daemon=True),
        threading.Thread(target=peer.sender, daemon=True),
        threading.Thread(target=peer.stdin_reader, daemon=True),
    ]
    [t.start() for t in th]

    try:
        while th[0].is_alive(): time.sleep(0.2)
    except KeyboardInterrupt:
        pass
    finally:
        peer.stop.set(); peer.end(); time.sleep(0.1)

if __name__ == "__main__":
    main()