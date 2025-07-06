# DHT-P2P-Net

## This will be a project in the background

Weird Botnet P2P request from my Email indox


![image](https://github.com/user-attachments/assets/99623939-b592-44e9-b4f9-f9fc53421b19)

I unexpectedly received a random .MD file in my inbox detailing the technical specifications for building a botnet architecture. The sender claimed it was a request and even offered between $30k–$100k for the source code. 😕 This repository exists to expose this kind of shady behavior and attempt to build an open-source variant instead, especially since the person stopped replying after several email exchanges asking about requirements he went silent.


![image](https://github.com/user-attachments/assets/0599802e-b7c2-4396-a968-91f00f945a14)

I'm not hating on the guy im just a bit suspisious. 

```mermaid
[Bot A] —FIND_NODE—> [Bot B]
[Bot B] —NODES—> [Bot A]
[Bot A] —FIND_VALUE—> [Bot C]
[Bot C] —VALUE (Command)—> [Bot A]
```

The .MD file content :- 
# P2P Botnet Technical Specification Document

> **Note**: This system is a decentralized botnet. Its core functions include command distribution, attack execution, node concealment and persistence, replay protection, and signature authentication. The network layer uses libp2p + Kademlia DHT to implement a control system that requires no central server.

---

## 1. Networking Layer

### 1.1 Architecture Design

- Implement peer-to-peer communication using [libp2p](https://github.com/libp2p/go-libp2p)
- Use Kademlia DHT as the medium for information distribution and lookup
- Each Bot node independently generates a PeerID and joins the DHT network

### 1.2 Bootstrapping

- On startup, connect to multiple built-in bootstrap nodes
- Address format supported: `/ip4/<IP>/tcp/<PORT>/p2p/<PeerID>`

### 1.3 Node Identity

- Generate/load libp2p RSA key pair
- Persist locally (default file: `peerkey`)

### 1.4 NAT Traversal

- Use libp2p NATPortMap to support UPnP/PCP port forwarding

---

## 2. Command & Control via DHT

### 2.1 Command Format

```json
{
  "command": "!udpflood 1.2.3.4 80 60",
  "timestamp": 1719412112,
  "signature": "<signature_data>",
  "ttl": 120
}
```

- `command`: Plaintext command string
- `timestamp`: Unix timestamp to prevent replay attacks
- `signature`: RSA PKCS1v15 signature
- `ttl`: Command validity period (in seconds)

### 2.2 Data Distribution

- Controller writes command to DHT via `PutValue("latest_attack_command", data)`
- Bot fetches command every 10 seconds using `GetValue`
- Validates using signature + time window check

### 2.3 Status Reporting

- Each bot reports JSON data via DHT key: `bot_stats_<PeerID>`
- Includes: uptime, last command time, total attack count, etc.

---

## 3. Security Mechanisms

### 3.1 Command Signature Verification

- Controller holds the unique RSA private key; Bot embeds the matching public key
- Validation process:
  1. Controller: Sign(SHA256(command + "|" + timestamp))
  2. Bot: rsa.VerifyPKCS1v15 + timestamp check + replay prevention

### 3.2 Anti-Debugging

- Checks `/proc/self/status` for TracerPid != 0 to detect debugger
- If debugging detected, bot exits immediately

### 3.3 Analysis Tool Defense

- Attempts to terminate known analysis tools such as `gdb`, `tcpdump`, `strace`, `ltrace`, `wireshark`
- Uses shell command: `pkill -9 <tool>`

### 3.4 Replay Protection

- Caches hash of each command to detect replays
- Performs cleanup every hour, retaining commands within the last 10 minutes

---

## 4. Other Modules (Brief Overview)

- **Command Execution**: Supports UDP/TCP/HTTP Flood
- **Persistence**: Installs as systemd service, auto-starts on boot
- **Logging**: Colored terminal output, supports debug tracing

---

## 5. Controller Suggestions

- Command signer: Generates signed commands using RSA private key
- Data viewer: Fetches and parses bot\_stats from DHT
- Automated delivery: Supports multi-node broadcast
- Optional: GUI / Web UI for management


