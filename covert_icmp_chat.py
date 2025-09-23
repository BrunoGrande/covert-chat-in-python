#!/usr/bin/env python3
import argparse
import os
import random
import select
import socket
import struct
import sys
import threading
import sys
import time
from typing import Optional, Tuple

# ---------- Protocol constants ----------
ICMP_ECHO_REPLY = 0  # Type 0
ICMP_CODE = 0
CTRL_START = 0b00
CTRL_MID   = 0b01
CTRL_IDLE  = 0b10  # reserved/unused here
CTRL_END   = 0b11

MAGIC_BYTE = 0xB7  # first START data byte to help sync/detect
SEND_INTERVAL = 0.08  # seconds between packets when streaming bytes
HANDSHAKE_INTERVAL = 0.5
RECV_TIMEOUT = 0.2
PADDING_LEN = 14  # extra bytes after the 2-byte header to look more "normal"
MAX_SEQ = 64

# ---------- Stego packing/unpacking ----------
def stego_pack(ctrl: int, seq: int, data_byte: int) -> bytes:
    """Pack [2 bits ctrl | 6 bits seq | 8 bits data] into 2 bytes."""
    ctrl &= 0b11
    seq &= 0b111111
    data_byte &= 0xFF
    first = (ctrl << 6) | seq
    return bytes([first, data_byte])

def stego_unpack(b: bytes) -> Tuple[int, int, int]:
    """Unpack the first 2 bytes into (ctrl, seq, data_byte)."""
    if len(b) < 2:
        raise ValueError("Payload too short")
    first, data_byte = b[0], b[1]
    ctrl = (first >> 6) & 0b11
    seq = first & 0b111111
    return ctrl, seq, data_byte

# ---------- Checksums ----------
def icmp_checksum(data: bytes) -> int:
    """Compute ICMP checksum."""
    if len(data) % 2:
        data += b"\x00"
    s = 0
    for i in range(0, len(data), 2):
        word = data[i] << 8 | data[i+1]
        s += word
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF

# ---------- Packet builders ----------
def build_icmp_echo_reply(identifier: int, sequence: int, payload: bytes) -> bytes:
    """Build ICMP Echo Reply packet (without IP header)."""
    header = struct.pack("!BBHHH", ICMP_ECHO_REPLY, ICMP_CODE, 0, identifier, sequence)
    chk = icmp_checksum(header + payload)
    header = struct.pack("!BBHHH", ICMP_ECHO_REPLY, ICMP_CODE, chk, identifier, sequence)
    return header + payload

def build_payload(ctrl: int, seq: int, data_byte: int) -> bytes:
    stego = stego_pack(ctrl, seq, data_byte)
    # Add benign-looking padding (timestamps, pid, jitter)
    pad = struct.pack("!I", int(time.time())) + struct.pack("!H", os.getpid() & 0xFFFF)
    # Ensure fixed-ish size, top up with random bytes to PADDING_LEN
    rnd = os.urandom(max(0, PADDING_LEN - len(pad)))
    return stego + pad + rnd

WINDOWS = sys.platform.startswith('win')

# ---------- Receiver (raw ICMP sniffer) ----------
def parse_ip_header(pkt: bytes) -> Tuple[int, int, str, str, int]:
    """Return (ihl_bytes, proto, src_ip, dst_ip, total_len)."""
    if len(pkt) < 20:  # min IP header
        raise ValueError("short IP packet")
    vihl = pkt[0]
    ihl = (vihl & 0x0F) * 4
    total_len = struct.unpack("!H", pkt[2:4])[0]
    proto = pkt[9]
    src_ip = socket.inet_ntoa(pkt[12:16])
    dst_ip = socket.inet_ntoa(pkt[16:20])
    return ihl, proto, src_ip, dst_ip, total_len

def parse_icmp(pkt: bytes, ihl: int) -> Tuple[int, int, int, int, bytes]:
    """Return (type, code, ident, seq, payload)."""
    icmp_hdr = pkt[ihl:ihl+8]
    if len(icmp_hdr) < 8:
        raise ValueError("short ICMP header")
    icmp_type, icmp_code, chk, ident, seq = struct.unpack("!BBHHH", icmp_hdr)
    payload = pkt[ihl+8:]
    return icmp_type, icmp_code, ident, seq, payload

class ChatPeer:
    def __init__(self, peer_ip: str, iface: Optional[str], verbose: bool):
        self.peer_ip = peer_ip
        self.peer_addr = None  # resolved IPv4 string
        self.iface = iface
        self.verbose = verbose
        self.raw_send = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        # Setting SO_BINDTODEVICE if iface provided (Linux only)
        if self.iface and not WINDOWS:
            try:
                self.raw_send.setsockopt(socket.SOL_SOCKET, 25, self.iface.encode() + b"\x00")  # SO_BINDTODEVICE=25
            except OSError:
                pass  # non-Linux/Windows or lacks perms
        # Receiver socket
        self.raw_recv = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        self.identifier = os.getpid() & 0xFFFF
        self.send_seq = 0
        self.recv_seq_last = None
        self.stop_event = threading.Event()
        self.role = None  # 'master' or 'slave'
        self.nonce = random.randint(0, 255)
        self.peer_nonce = None
        self.handshaked = False
        self.input_queue = []
        self.lock = threading.Lock()

    def log(self, *a):
        if self.verbose:
            print(*a, flush=True)

    def resolve_peer(self, attempts: int = 120, delay: float = 0.5):
        """Resolve peer name to IPv4 with retries (Docker DNS can be slow to register)."""
        for i in range(attempts):
            try:
                self.peer_addr = socket.gethostbyname(self.peer_ip)
                self.log(f"[dns] {self.peer_ip} -> {self.peer_addr}")
                return True
            except socket.gaierror:
                if i == 0:
                    print(f"[dns] waiting for {self.peer_ip} to resolve...", flush=True)
                time.sleep(delay)
        print(f"[dns] failed to resolve {self.peer_ip}", flush=True)
        return False

    def next_seq(self) -> int:
        val = self.send_seq
        self.send_seq = (self.send_seq + 1) % MAX_SEQ
        return val

    def send_frame(self, ctrl: int, data_byte: int):
        seq = self.next_seq()
        payload = build_payload(ctrl, seq, data_byte)
        pkt = build_icmp_echo_reply(self.identifier, seq, payload)
        try:
            if not self.peer_addr and not self.resolve_peer():
                return
            self.raw_send.sendto(pkt, (self.peer_addr, 0))
        except socket.gaierror:
            if self.resolve_peer():
                try:
                    self.raw_send.sendto(pkt, (self.peer_addr, 0))
                except Exception as e:
                    self.log(f"[send error after re-resolve] {e}")
            else:
                self.log("[send error] DNS not resolved")
        except PermissionError:
            print("[!] Need root privileges to send raw ICMP. Run with sudo.", file=sys.stderr)
            os._exit(2)
        except Exception as e:
            self.log(f"[send error] {e}")

    def receiver_loop(self):
        self.raw_recv.settimeout(RECV_TIMEOUT)
        while not self.stop_event.is_set():
            try:
                pkt, addr = self.raw_recv.recvfrom(65535)
            except socket.timeout:
                continue
            except Exception as e:
                self.log(f"[recv error] {e}")
                continue
            try:
                if WINDOWS:
                    src = addr[0]
                    if len(pkt) < 8:
                        continue
                    icmp_type, icmp_code, ident, seq = struct.unpack('!BBHH', pkt[:6] + b'\x00\x00')[:4]
                    # above trick to reuse format, but better to unpack directly:
                    icmp_type, icmp_code, chk, ident, seq = struct.unpack('!BBHHH', pkt[:8])
                    payload = pkt[8:]
                else:
                    ihl, proto, src, dst, tlen = parse_ip_header(pkt)
                    if proto != socket.IPPROTO_ICMP:
                        continue
                    icmp_type, icmp_code, ident, seq, payload = parse_icmp(pkt, ihl)
                # Only care Echo Reply (our channel) from the peer
                peer_ok = (src == self.peer_ip) or (self.peer_addr is not None and src == self.peer_addr)
                if icmp_type != ICMP_ECHO_REPLY or not peer_ok:
                    continue
                if len(payload) < 2:
                    continue
                ctrl, pseq, data = stego_unpack(payload[:2])
            except Exception as e:
                self.log(f"[parse error] {e}")
                continue

            # Handshake / role negotiation
            if not self.handshaked:
                if ctrl == CTRL_START and data == MAGIC_BYTE:
                    self.log(f"[handshake] peer START+MAGIC seen")
                elif ctrl == CTRL_START and data != MAGIC_BYTE:
                    self.peer_nonce = data
                    if self.peer_nonce is not None:
                        if self.nonce > self.peer_nonce:
                            self.role = 'master'
                        elif self.nonce < self.peer_nonce:
                            self.role = 'slave'
                        else:
                            self.role = 'master' if self.identifier > ident else 'slave'
                        self.handshaked = True
                        self.log(f"[handshake] role={self.role}, my_nonce={self.nonce}, peer_nonce={self.peer_nonce}")
                        print(f"[+] Negotiated role: {self.role}", flush=True)
                        continue
                continue  # wait until handshaked

            # After handshake: data flow
            if ctrl == CTRL_MID:
                # normal chat byte
                sys.stdout.write(chr(data))
                sys.stdout.flush()
            elif ctrl == CTRL_END:
                print("\n[+] Peer ended the chat.", flush=True)
                self.stop_event.set()
                break

    def stdin_loop(self):
        #\"\"\"Read from stdin and enqueue bytes to send as CTRL_MID.\"\"\"
        # non-blocking read via select
        while not self.stop_event.is_set():
            r, _, _ = select.select([sys.stdin], [], [], 0.1)
            if sys.stdin in r:
                chunk = os.read(sys.stdin.fileno(), 1024)
                if not chunk:
                    # EOF
                    self.stop_event.set()
                    break
                with self.lock:
                    self.input_queue += list(chunk)
            else:
                time.sleep(0.05)

    def sender_loop(self):
        # Ensure peer is resolvable before we start sending
        if not self.resolve_peer():
            self.stop_event.set()
            return
        # 1) Handshake: broadcast START + MAGIC then START + nonce until role decided
        t0 = time.time()
        sent_magic = False
        while not self.stop_event.is_set() and not self.handshaked:
            now = time.time()
            if (not sent_magic) or (now - t0) > HANDSHAKE_INTERVAL:
                self.send_frame(CTRL_START, MAGIC_BYTE)
                sent_magic = True
                t0 = now
                self.log("[handshake] sent START+MAGIC")
                time.sleep(HANDSHAKE_INTERVAL/2)
                self.send_frame(CTRL_START, self.nonce)
                self.log(f"[handshake] sent START+NONCE={self.nonce}")
            time.sleep(0.1)

        if not self.handshaked:
            # Someone pressed Ctrl+C early
            return

        # 2) Data phase: stream bytes from input_queue
        while not self.stop_event.is_set():
            b = None
            with self.lock:
                if self.input_queue:
                    b = self.input_queue.pop(0)
            if b is not None:
                self.send_frame(CTRL_MID, b)
                time.sleep(SEND_INTERVAL)
            else:
                time.sleep(0.02)

    def end(self):
        try:
            self.send_frame(CTRL_END, 0x00)
        except Exception:
            pass

def main():
    ap = argparse.ArgumentParser(description="Covert ICMP chat (Type 0 Echo Reply) single-file with role negotiation.")
    ap.add_argument("--peer", required=True, help="Peer IPv4 address")
    ap.add_argument("--iface", default=None, help="Bind send socket to interface (Linux only, e.g., eth0)")
    ap.add_argument("--verbose", action="store_true", help="Verbose logs")
    args = ap.parse_args()

    peer = ChatPeer(args.peer, args.iface, args.verbose)
    print("[*] Covert ICMP chat starting. Type your message and press Enter. Ctrl-D to end.", flush=True)

    recv_t = threading.Thread(target=peer.receiver_loop, daemon=True)
    send_t = threading.Thread(target=peer.sender_loop, daemon=True)
    stdin_t = threading.Thread(target=peer.stdin_loop, daemon=True)
    recv_t.start()
    send_t.start()
    stdin_t.start()

    try:
        while recv_t.is_alive():
            time.sleep(0.2)
    except KeyboardInterrupt:
        pass
    finally:
        peer.stop_event.set()
        peer.end()
        time.sleep(0.1)

if __name__ == "__main__":
    main()
