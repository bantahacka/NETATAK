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

# ARP Host Scanner
# Scans for host(s) on a given network using ARP
# This module is used to scan a single IP or network for hosts via ARP
# Timeout and interval can be adjusted when initiating the scan

from scapy.all import *
import ipaddress

# Define text colours
B, R, Y, G, M, N = '\33[94m', '\033[91m', '\33[93m', '\033[1;32m', '\033[1;35m', '\033[0m'

# Define the class
class ARPscanner:
    def __init__(self, target, timeout, interval, inc_mac, count):
        self.target = target
        self.count = count
        self.timeout = timeout
        self.interval = interval
        self.inc_mac = inc_mac
        self.active_hosts = []
        self.ipdict = {}

    def arpscan(self):
        print("{0}[*] Running %d ARP scan(s) against %s with an interval of %4.1fs and a timeout of %ds".format(N) % (self.count, self.target, self.interval, self.timeout))
        # Run an ARP scan against the target machine/network. If machine responds, output the IP that responded. Build a target list if inc_mac is set to 1
        total_resps = 0
        total_scans = 0

        try:
            for i in range(self.count):
                total_scans = i+1
                ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=self.target), verbose=0, inter=self.interval, timeout=self.timeout)
                for snd, rcv in ans:
                    ipaddr = rcv.sprintf(r"%ARP.psrc%")
                    print("{0}[*] {1} responded to ARP request.".format(G, ipaddr))
                    if ipaddr not in self.active_hosts:
                        self.active_hosts.append(ipaddr)
                        total_resps += 1
                        if self.inc_mac == 1:
                            ipmac = rcv.sprintf(r"%Ether.src%")
                            self.ipdict[total_resps] = ipaddr + '-' + ipmac
                print("{0}[*] {1} Target(s) responded to ARP".format(G, total_resps))
                print("{0}[*] Scans completed: {1} of {2}".format(G, total_scans, self.count))
                if total_scans < self.count:
                    continue;
                if self.inc_mac == 0:
                    return True;
            if len(self.ipdict) == 0:
                print("{0}[*] No targets found via ARP. Exiting...".format(R))
                return False
            if self.inc_mac == 1 and len(self.ipdict) > 0:
                print("{0}[*] Target(s) responded to ARP request. Target list generated.".format(G))
                return self.ipdict
        except KeyboardInterrupt:
            print("{0}[*] ARP Scan cancelled by user.".format(R))
            return False