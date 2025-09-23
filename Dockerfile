# syntax=docker/dockerfile:1
FROM python:3.12-slim

# Avoid interactive tzdata
ENV DEBIAN_FRONTEND=noninteractive

# Install tcpdump and basic net tools (tiny footprint)
RUN apt-get update && apt-get install -y --no-install-recommends \
    tcpdump iproute2 iputils-ping ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# Workdir
WORKDIR /app

# Copy the single-file chat script
COPY covert_icmp_chat.py /app/covert_icmp_chat.py

# Default runs help
ENTRYPOINT ["python", "/app/covert_icmp_chat.py"]
