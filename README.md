# NETATAK
NETATAK - A suite of network scanning and attack tools.
Version: 0.7b

Supported OS: Windows 11 and Linux

Supported Python Version:
3.5 or greater

## Windows 11

Run NETATAK from an elevated PowerShell or Command Prompt. Install Npcap with
WinPcap API-compatible mode enabled, then install Scapy with the same Python
interpreter used to launch the program:

```powershell
py -m pip install scapy
py .\netatak.py
```

ARP and ICMP scanning use Scapy and require Npcap. The ARP MITM and DNS
spoofing tools depend on Linux IP forwarding and remain unavailable on Windows.

## Scanner settings

Choose `s` from the main menu to configure the scan interface, ICMP attempts,
and output format. ARP uses the selected interface; ICMP uses Scapy's route-
selected L3 interface and records it in the result. Text output is displayed
in the terminal. JSON is printed as structured data, and CSV writes one row
per discovered or tested address. Scanners currently support IPv4 targets.
Use `q` to exit the menu cleanly.

Disclaimer: NETATAK has been developed for educational and testing purposes only.
It must not be used in production environments unless explicit permission has been granted e.g. for penetration testing.
Use of this tool suite is at your own risk, and I will not be held responsible for any system damage or data loss as a result of its use.
If using NETATAK, always ensure you comply with local and international laws.
