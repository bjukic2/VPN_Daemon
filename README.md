# Secure Custom VPN - C & Libsodium

This is a lightweight, high-performance custom VPN client written entirely in **C**. It is designed to securely route all system traffic through a remote virtual private server (e.g., Oracle Cloud), effectively bypassing Carrier-Grade NAT (CGNAT) restrictions typical of ISP connections like Starlink, while ensuring zero IPv6 leakage.

---

## Tech Stack

- **Language**: C
- **Cryptography**: [Libsodium](https://doc.libsodium.org/)
- **Networking**: Linux TUN/TAP interfaces, UDP Sockets
- **System APIs**: POSIX, `ioctl`, `select()` for non-blocking I/O
- **Routing**: `iproute2`, Linux Kernel IPv4/IPv6 routing tables

---

## Core Architecture

### Why a Custom VPN?
Standard VPN solutions can sometimes struggle with strict CGNAT environments or have complex configurations. This project provides a heavily customized, self-contained client that handles its own routing, network abstraction, and encryption without relying on external bash scripts or heavy third-party VPN daemons. 

### Encryption & Handshake
The tunnel uses **Libsodium** for state-of-the-art cryptography. It generates secure session keys using `crypto_kx` (X25519 key exchange) and encrypts all packets end-to-end using `crypto_secretbox` (XSalsa20-Poly1305) with dynamic nonces, ensuring data integrity and confidentiality.

### Automated Routing & IPv6 Leak Prevention
To redirect traffic, the client dynamically creates a `tun` interface and injects `0.0.0.0/1` and `128.0.0.0/1` routes. This approach elegantly overrides the default gateway without deleting it. 
To prevent **IPv6 leaks** (a common issue with Starlink and modern ISPs), the client injects an `unreachable` metric for IPv6 default routes. This acts as a temporary blackhole for IPv6 traffic without disabling the kernel's IPv6 stack, allowing for instant network recovery upon termination.

---

## Features

- **End-to-End Encryption**: Military-grade packet encryption using Libsodium.
- **CGNAT Bypass**: Successfully pierces through strict NAT environments (tested on Starlink) by establishing an outbound UDP tunnel to a cloud VPS.
- **Zero IPv6 Leakage**: Implements an active IPv6 blackhole routing technique instead of legacy `sysctl` modifications.
- **Self-Contained Network Management**: The C binary handles TUN interface creation, MTU adjustments, IP assignment, and route injection internally.
- **Graceful Termination**: Captures `SIGINT` (Ctrl+C) to safely clean up routing tables, tear down the TUN interface, and instantly restore the host's original network state.
- **Non-blocking I/O**: Efficient packet multiplexing between the virtual interface and the UDP socket using `select()`.

---

## Getting Started

### 1. Prerequisites
This client runs on Linux and requires the Libsodium development library. 

Install the required dependencies (Ubuntu/Debian):

```bash
sudo apt update
sudo apt install build-essential libsodium-dev
```

### 2. Clone the repository

```bash
git clone [https://github.com/bjukic2/CustomVPN.git](https://github.com/bjukic2/CustomVPN.git)
cd CustomVPN
```

### 3. Compile the client

Use `gcc` to compile the source code, making sure to link the Libsodium library:

```bash
gcc vpn_client.c -o vpn_client -lsodium
```

### 4. Run the application

The client must be executed with root privileges to create virtual network interfaces and modify kernel routing tables.

```bash
sudo ./vpn_client
```
> **Note:** Once started, all system IPv4 traffic is encrypted and routed through the remote server. IPv6 traffic is safely dropped to prevent leaks. Press `Ctrl + C` at any time to gracefully close the tunnel and restore your local internet connection.

---

## Author

Made by **Bruno Jukić**  
[https://github.com/bjukic2](https://github.com/bjukic2)