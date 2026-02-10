# 👑 STP Root Bridge Attack Tool (PoC)

**Course:** Network Security (Seguridad Informática)
**Student:** Junior (ID: 2024-2015)
**Language:** Python 3 (Scapy Framework)

---

## ⚠️ Disclaimer
**EDUCATIONAL USE ONLY.**
This script is designed for academic purposes and authorized security testing only. Manipulating the Spanning Tree Protocol (STP) in a production environment can cause severe network instability, loops, and denial of service (DoS). Use responsibly.

---

## 1. Project Overview
This tool demonstrates a **Layer 2 Man-in-the-Middle (MitM)** attack by exploiting the **Spanning Tree Protocol (STP/802.1D)**.

The script injects forged **Bridge Protocol Data Units (BPDUs)** into the network, claiming to have the lowest Bridge Priority (`0`). This forces the legitimate switches to recalculate the topology and elect the attacker's machine as the **Root Bridge**. Once successful, significant network traffic may flow through the attacker's device.

### Key Features
* **Packet Injection:** Sends raw Ethernet frames using Scapy.
* **Priority Spoofing:** Sets the STP Priority to `0` (Maximum preference).
* **Persistence:** Continuously sends BPDUs to maintain the Root status.

---

## 2. Network Topology Setup
* **Attacker:** Kali Linux (vmnet adapter).
* **Victim:** Cisco 3725 Router (with NM-16ESW Switch Module).
* **Protocol:** IEEE 802.1D (Classic STP).

> **Note:** The attack works by connecting the attacker directly to a switch port (access layer).

---

## 3. Installation & Usage

### Prerequisites
* Python 3.x
* Scapy library
* Root privileges (required for raw socket access)

```bash
# 1. Clone the repository
git clone [https://github.com/deiviRd18/D31B1-STP-Root-Attack.git](https://github.com/deiviRd18/D31B1-STP-Root-Attack.git)

# 2. Install dependencies
pip3 install scapy

```
Execution
Run the script with sudo to allow network injection:

Bash
`sudo python3 d31b1_stp_root.py`

Mitigation Strategies

To defend against this attack in a real-world scenario, implement STP Security features:

BPDU Guard: Automatically disables a port if it receives a BPDU on an access port.

```Cisco CLI
Switch(config-if)# spanning-tree bpduguard enable
```
Root Guard: Prevents a port from becoming a Root Port. If a superior BPDU is received, the port goes into a root-inconsistent state.

```Cisco CLI
Switch(config-if)# spanning-tree guard root
