# Covert ICMP Chat — Simple README (Static-IP Docker)

This lab spins up **two containers** (`peera`, `peerb`) that exchange text covertly using **ICMP Echo Reply (Type 0)**.  
We keep it **simple**: static IPs (`10.0.0.10` and `10.0.0.11`), no DNS, and a tiny 2‑byte header at the start of each ICMP payload.

---

## What you should know (30s)
- **ICMP Type 0 = Echo Reply** (we forge replies directly).
- Each packet’s payload starts with a **2‑byte stego header**:
  - Layout: `[ 2 bits ctrl | 6 bits seq | 8 bits data ]`
  - `ctrl`: `00=START`, `01=MID` (data), `11=END` (we keep `10=IDLE` reserved).
  - `seq`: 0..63, to keep a sense of order.
  - `data`: the **single byte** you typed (one packet per byte).
- **Handshake**: both sides send `START+MAGIC` then `START+NONCE` (random 1B).  
  Higher nonce ⇒ **master**; the other side ⇒ **slave** (tie-breaker by PID).

---

## Project layout
```
.
├─ Dockerfile
├─ docker-compose.yml          # static IPs: 10.0.0.10 (A), 10.0.0.11 (B)
├─ covert_icmp_chat.py         # single-file chat
└─ captures/                   # bind mount for .pcap files
```

---

## Quickstart (two terminals)
From the project folder:

```bash
mkdir -p captures
docker compose up --build -d

# Terminal A
docker attach icmp_peera

# Terminal B
docker attach icmp_peerb
```
Type in either terminal and press **Enter** to send.  
Detach without killing: **Ctrl-p**, **Ctrl-q**.

You should see something like:
```
[*] Covert ICMP chat. Type and press Enter. Ctrl-D to end.
[hs] peer MAGIC
[+] role: master   # or slave
```

---

## Capture PCAPs (for the report)
Start the capture **before** you type, and capture on **eth0** inside the container:

```bash
# A side
docker exec -it icmp_peera tcpdump -i eth0 -nn -vvv "icmp and icmp[0]==0" -w /captures/peerA.pcap
# B side
docker exec -it icmp_peerb tcpdump -i eth0 -nn -vvv "icmp and icmp[0]==0" -w /captures/peerB.pcap
```
Press **Ctrl-C** to stop. The files will appear on the host in `./captures/`.

**Wireshark tips**  
- Display filter: `icmp && icmp.type == 0`  
- Our 2‑byte header is the **first two bytes** of the ICMP payload:
  - Byte0: `ctrl(2b) | seq(6b)`
  - Byte1: `data` (ASCII of the char you typed)

---

## How the code works (short & sweet)

### 1) ICMP builder + checksum
We construct an **Echo Reply** header and compute the ICMP checksum over `header + payload`. The IP header is handled by the raw socket.

### 2) Stego header (2 bytes)
At the start of the payload we pack:
```
ctrl (2 bits) | seq (6 bits) | data (8 bits)
```
This gives minimal framing so we can mark **start**, **data**, and **end**.

### 3) Handshake, then chat
- Handshake: send `START+MAGIC (0xB7)` and `START+NONCE`. Higher nonce ⇒ master.  
- Chat: each byte from **stdin** becomes a `MID` frame (one packet per byte).  
- End: on EOF/Ctrl‑C we send a final `END` frame.

### 4) Static IP assumptions
- We pass `--peer 10.0.0.10/11` directly (no DNS).
- On Docker bridges the IPv4 header is standard (IHL=20), so parsing is trivial.
- We also filter by `src IP == peer IP` to only accept the other side’s packets.

---

## Troubleshooting
- **No packets in pcap** → Start `tcpdump` **before** typing; capture on `eth0` (not `any`).  
- **Ping works but chat doesn’t** → Make sure you **attached** to both containers and pressed **Enter**.  
- **`tcpdump` permission** → add `NET_ADMIN` alongside `NET_RAW` in `docker-compose.yml`, rebuild.  
- **Subnet conflict** → If `10.0.0.0/24` is in use on your host, change the compose subnet (e.g., `10.123.0.0/24`) and update the two IPs accordingly.

---

## Stop everything
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
(Use `-v` to remove bind volume contents, if you created any.)

---