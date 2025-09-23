# Covert ICMP Chat — Deep Dive (Dockerized on `python:3-slim`)

This repo spins up **two containers** (`peera`, `peerb`) to run a **single-file covert chat** over **ICMP Echo Reply (Type 0)**.  
Steganographic header: **2 bytes** at the start of the ICMP payload → **`[2 bits ctrl | 6 bits seq | 8 bits data]`**.

The design follows your class brief: *hide data inside ICMP payload*, keep header minimal, and demonstrate a bidirectional chat with pcap evidence.

---

## Table of Contents
1. Concepts & Rationale  
   1.1 Why ICMP Echo Reply (Type 0)  
   1.2 Stego Header Spec  
   1.3 Chat Flow & Roles  
2. Project Layout  
3. Prereqs & Environment  
4. Quickstart (Two-Terminal Interactive)  
5. Capturing PCAPs  
6. Troubleshooting & Tips  
7. Code Walkthrough (`covert_icmp_chat.py`)  
   7.1 Constants & Protocol Packing  
   7.2 Checksum & ICMP Builder  
   7.3 Payload Builder & Padding  
   7.4 `ChatPeer` Class  
   7.5 `main()` Bootstrap  
8. Security Notes & Detectability  
9. Extending the Project

---

## Concepts & Rationale

### Why ICMP Echo Reply (Type 0)
- The assignment explicitly requires using **Type 0 (Echo Reply)** for covert transfer.  
- We **forge replies** directly to the peer; we are not responding to a request. This is unusual in the wild (normally `Type 8` request → `Type 0` reply), which is exactly the covert channel gimmick here.  
- **Checksum** must be correct; many IDS stacks flag malformed ICMP.

> ⚠️ Common pitfall: **Type 8 = Echo Request**, **Type 0 = Echo Reply**. We use **Type 0**.

### Stego Header Spec
We embed **exactly 2 bytes** at the start of the payload:

```
bit 15        10       5        0
    | 2 bits | 6 bits | 8 bits |
    |  ctrl  |  seq   |  data  |
```

- **`ctrl`** (2 bits):  
  - `00` = START  
  - `01` = MID (normal streaming)  
  - `10` = IDLE (reserved, optional keepalive)  
  - `11` = END
- **`seq`** (6 bits): 0..63 wraps around (local to the stego layer; **not** the ICMP header `sequence` field).  
- **`data`** (8 bits): one **byte** per ICMP packet (minimalistic on purpose).

**Sync/Magic**: the very first `START` carries **`data=0xB7`**, acting as a practical magic byte for session identification (no expansion of the header size).

### Chat Flow & Roles
- Both peers start the same script.  
- Each broadcasts `START+MAGIC` then `START+NONCE` (1-byte random).  
- **Election**: higher `nonce` ⇒ **master**, lower `nonce` ⇒ **slave**. Tie-breaker by process identifier.  
- After handshake, both stream keystrokes as `MID` frames; `END` is sent on EOF or Ctrl‑C.

---

## Project Layout

```
.
├─ Dockerfile                 # python:3.12-slim + tcpdump + tooling
├─ docker-compose.yml         # two services (peera, peerb) with interactive TTY/stdin
├─ covert_icmp_chat.py        # the entire chat in a single file
└─ captures/                  # bind-mounted; stores peerA.pcap / peerB.pcap
```

---

## Prereqs & Environment
- Docker Engine (Linux or Docker Desktop for Windows/macOS).  
- No special kernel modules in the host: containers run as **root** and request **CAP_NET_RAW** to open raw ICMP sockets.

> If your engine blocks `tcpdump` capture, add **`NET_ADMIN`** or use `--privileged` (only for local labs).

---

## Quickstart (Two-Terminal Interactive)

```bash
# 0) from the project directory
mkdir -p captures

# 1) build & start both peers (detached)
docker compose up --build -d

# 2) open TWO terminals and attach:
docker attach icmp_peera      # Terminal A
docker attach icmp_peerb      # Terminal B

# 3) type in either terminal and press Enter → message flows via ICMP Type 0

# detach without killing containers:
#   Ctrl-p  Ctrl-q
```

**What you should see:**
- `[*] Covert ICMP chat starting...`  
- `[dns] peerb -> <IP>` / `[dns] peera -> <IP>` when Docker DNS resolves.  
- After handshake: `"[+] Negotiated role: master"` or `"slave"`.

---

## Capturing PCAPs

```bash
docker exec -it icmp_peera tcpdump -i any -w /captures/peerA.pcap icmp
docker exec -it icmp_peerb tcpdump -i any -w /captures/peerB.pcap icmp
# Ctrl-C to stop.
# Files appear on host in ./captures/
```

If `tcpdump` complains:
- Add to the service: `cap_add: [NET_ADMIN]`, or
- Temporarily run capture with `--privileged` (lab-only).

**Filter tips in Wireshark/TShark:**
- Show only Echo Reply: `icmp && icmp.type == 0`  
- Highlight our header: look at the **first 2 bytes of payload**.

---

## Troubleshooting & Tips
- **Name or service not known:** Docker DNS can lag. The script now **retries resolving** `peera`/`peerb` until ready.  
- **Nothing prints:** you must **attach** (we read from stdin). Hit **Enter** after typing.  
- **Containers stop after a minute:** add/keep `stdin_open: true` and `tty: true`; attach to each container.  
- **PCAP empty:** ensure `tcpdump` is running during your chat; check the right interface (`any` works in containers).  
- **Windows host:** irrelevant; the containers run Linux (raw sockets OK).

---

## Code Walkthrough (`covert_icmp_chat.py`)

This section explains the code **top to bottom** so you can defend it in an oral exam and tweak confidently.

### 7.1 Constants & Protocol Packing

```py
ICMP_ECHO_REPLY = 0
ICMP_CODE = 0
CTRL_START, CTRL_MID, CTRL_IDLE, CTRL_END = 0b00, 0b01, 0b10, 0b11
MAGIC_BYTE = 0xB7
MAX_SEQ = 64
```

- **`stego_pack(ctrl, seq, data)`** and **`stego_unpack(b)`** convert the 2-byte stego header to/from integers:
```py
first = (ctrl & 0b11) << 6 | (seq & 0b111111)
return bytes([first, data_byte & 0xFF])
```
- The **6-bit seq** is local to our stego layer; it is **not** the field `sequence` of ICMP header.

### 7.2 Checksum & ICMP Builder

**`icmp_checksum(data)`**: standard 16-bit one’s complement of the one’s complement sum over the ICMP message.  
- If data length is odd → pad with `0x00`.  
- Accumulate 16-bit words, fold carries, and finally invert (`~s & 0xFFFF`).

**`build_icmp_echo_reply(identifier, sequence, payload)`**:
1. Build a temporary ICMP header with checksum `0`.  
2. Compute checksum over header+payload.  
3. Repack header with the real checksum.  
4. Return `header + payload` (IP header is **not** added — raw ICMP socket takes care of IP).

### 7.3 Payload Builder & Padding

**`build_payload(ctrl, seq, data_byte)`**:
- Prefix **stego header (2 bytes)**.  
- Add benign-looking padding: UNIX timestamp (4B), PID (2B), and random bytes to reach a small padded size.  
- Rationale: payloads with a few metadata-looking bytes are less suspicious than tiny or perfectly regular payloads.

### 7.4 `ChatPeer` Class

#### Constructor
- Creates **two raw sockets** (`AF_INET`, `SOCK_RAW`, `IPPROTO_ICMP`): one for sending, one for receiving.  
- Stores `identifier = pid & 0xFFFF` to fill the ICMP `identifier` field.  
- Initializes sequence counters, role state, random `nonce`, and a thread-safe queue for keystrokes.

#### DNS Resolution Helper
**`resolve_peer()`**  
- Repeatedly calls `socket.gethostbyname(peer_name)` until Docker DNS is ready.  
- Caches the resolved IPv4 in `self.peer_addr`.  
- Sender won’t start until resolve succeeds.

#### Sending Frames
**`send_frame(ctrl, data_byte)`**  
- Advances local `send_seq` (0..63).  
- Builds payload (`stego header` + padding), then ICMP Echo Reply with our `identifier` and `sequence` (ICMP field).  
- Sends to `(self.peer_addr, 0)` with retries if DNS hiccups.

#### Receiving Loop
**`receiver_loop()`**
- Blocks on the raw socket, reading IP packets.  
- Parses IP header to find where ICMP starts, then unpacks `type`, `code`, `identifier`, `sequence`.  
- **Filters**: only `type == 0` (Echo Reply) **from our peer** (matches by hostname or resolved IP).  
- Reads first 2 bytes of the payload → `stego_unpack` → `(ctrl, seq, data)`.  
- **Handshake handling:**  
  - `START` + `MAGIC` → note peer is alive.  
  - `START` + `nonce` → compare nonces, elect role, set `handshaked = True`.  
- **Data handling:**  
  - `MID` → prints `chr(data)` to stdout (chat).  
  - `END` → sets `stop_event` and breaks.

#### Stdin Loop
**`stdin_loop()`**
- Uses `select` to read from stdin without blocking; enfileira bytes (keystrokes) para envio.

#### Sender Loop
**`sender_loop()`**
1. **Resolve** peer DNS.  
2. Handshake: send `START+MAGIC`, wait a beat, send `START+NONCE`, repeat until we receive peer nonce and negotiate.  
3. Data phase: pop bytes from the queue and send as `MID`.  
4. Throttle with `SEND_INTERVAL` to avoid flooding.

#### Graceful End
**`end()`**  
- Attempts a final `END` frame when stopping.

### 7.5 `main()` Bootstrap
- Parses CLI args: `--peer`, `--iface` (ignored in Docker), `--verbose`.  
- Spawns **three threads**: receiver, sender, and stdin.  
- Prints a banner and keeps the main thread alive.

---

## Security Notes & Detectability
- **Echo Reply without a corresponding Request** is not standard behavior; on strict networks this can be flagged. In a lab/bridge network, it’s fine.  
- Throughput is intentionally tiny (1 byte/pkt). Faster channels are noisier and easier to flag.  
- Padding makes payloads a bit less uniform; you can tweak it to simulate OS ping patterns.  
- If you want to look more “normal,” consider:  
  - Random gaps between sends (`SEND_INTERVAL` jitter),  
  - Occasional `IDLE` frames (keepalive),  
  - Varying payload lengths (still keeping the first 2 bytes as header).

---

## Extending the Project
- **Acks & reliability**: add an ack bit and re‑transmit on seq gap.  
- **Chunking**: add LEN field after the 2‑byte header (increases overhead, but gives multi‑byte payloads).  
- **Encryption**: XOR with a pre-shared key or (better) AEAD on the data byte stream (requires framing for IV/nonce).  
- **Auto-capture**: run `tcpdump` as a background sidecar per peer and rotate files in `/captures`.

---

## Runbook (TL;DR)

```bash
# build + start
docker compose up --build -d

# attach (two terminals)
docker attach icmp_peera
docker attach icmp_peerb

# capture pcaps (optional)
docker exec -it icmp_peera tcpdump -i any -w /captures/peerA.pcap icmp
docker exec -it icmp_peerb tcpdump -i any -w /captures/peerB.pcap icmp

# stop
docker compose down
```
