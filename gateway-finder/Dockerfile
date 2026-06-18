FROM python:3.11-slim

LABEL maintainer="KiranKurbet"
LABEL description="GatewayFinder — Gateway Intelligence Engine"

# System deps for scapy + netifaces
RUN apt-get update && apt-get install -y --no-install-recommends \
        libpcap-dev \
        iproute2 \
        iputils-ping \
        arp-scan \
        nmap \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
RUN pip install --no-cache-dir -e .

# Run as root inside the container so scapy/ARP work
# (container is isolated; map --network=host for full LAN access)
ENTRYPOINT ["gf"]
CMD ["--help"]
