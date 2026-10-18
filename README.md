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

All tools use Scapy and require Npcap on Windows. The ARP MITM and DNS spoofing
tools work on both Windows and Linux: IP forwarding is enabled via
`Set-NetIPInterface` on Windows and `/proc/sys/net/ipv4/ip_forward` on Linux, and
is turned back off when the tool stops. Run from an elevated/root terminal.

## Linux

Run NETATAK as root. Install Scapy with the same interpreter used to launch it:

```bash
sudo python3 -m pip install scapy
sudo python3 ./netatak.py
```

## Attack tools (ARP MITM & DNS spoofing)

Options `3` (ARP Man-In-The-Middle) and `4` (DNS Spoofer) poison the target and
gateway ARP caches so traffic is relayed through the host running NETATAK, which
requires IP forwarding (handled automatically, see above). The DNS spoofer answers
queries for domains listed in `atktools/config/dnspoof/spooflist.csv` (format:
`domain,ip_to_reply_with`, one per line; matches the domain and its subdomains) and
forwards everything else untouched.

Press `CTRL+C` to stop either tool. This runs the graceful cleanup: the ARP caches
are restored and IP forwarding is disabled. If a run is instead hard-killed (for
example `kill -9`, Task Manager, or a crash), that cleanup is skipped and the
target is left poisoned with forwarding still on. Recover with:

```bash
python netatak.py --restore <TARGET_IP> <GATEWAY_IP>
```

This re-ARPs the target and gateway and turns IP forwarding back off, then exits.

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
