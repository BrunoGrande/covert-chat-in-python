# Covert ICMP Chat — Dockerized (python:3-slim)

This spins up **two containers** (peerA, peerB) running the single-file covert ICMP chat using **ICMP Echo Reply (Type 0)** with a 2‑byte stego header. Each container has `NET_RAW` to allow raw sockets. Use Docker Desktop or Linux Docker.

## Files
- `Dockerfile` — builds from `python:3.12-slim`, installs `tcpdump` and net tools.
- `docker-compose.yml` — brings up two peers on a user bridge network; DNS names `peerA`/`peerB` resolve to each other.
- `covert_icmp_chat.py` — the single Python file you already asked for.
- `captures/` — host folder bind-mounted to both containers for easy `.pcap` export.

## Quickstart
```bash
# 1) Put the three files in the same dir (as they are here)
# 2) Build and start
docker compose up --build -d

# 3) Attach to a peer to chat (type and press Enter)
docker attach icmp_peerA
# in another terminal:
docker attach icmp_peerB

# Detach without killing: Ctrl-p Ctrl-q (Docker key combo)

# 4) Capture pcaps (require NET_ADMIN? No: tcpdump works with CAP_NET_RAW for sniffing on 'any' in most setups)
docker exec -it icmp_peerA tcpdump -i any -w /captures/peerA.pcap icmp
docker exec -it icmp_peerB tcpdump -i any -w /captures/peerB.pcap icmp
# Hit Ctrl-C to stop capture; files appear on host in ./captures/
```

> If `tcpdump` says "You don't have permission to capture", add `cap_add: [NET_ADMIN]` to the service, or run with `--privileged` (last resort), depending on your Docker engine policy.

## Notes
- Both containers run as **root** to open raw sockets.
- We rely on Docker DNS: `--peer peerB` and `--peer peerA` (no static IP juggling).
- The script prints the negotiated role (**master/slave**) automatically after handshake.
- To stop everything:
```bash
docker compose down
```
