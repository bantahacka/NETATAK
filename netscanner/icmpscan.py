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

# ICMP Host Scanner
# Scans for host(s) on a given network using ICMP
# This module is used to scan a single IP or network for hosts via ICMP
# Ping count, timeout and packet interval can be adjusted when initiating the scan

import time
from scapy.all import *

# Define text colours
B, R, Y, G, M, N = '\33[94m', '\033[91m', '\33[93m', '\033[1;32m', '\033[1;35m', '\033[0m'

# Define the class
class ICMPscanner:
    def __init__(self, target, count, timeout, pktinterval):
        self.target = target
        self.count = count
        self.timeout = timeout
        self.pktinterval = pktinterval
        self.active_hosts = []

    def icmpscan(self):
        # Run an ICMP scan against the target machine/network and report any hosts that are alive.
        print("{0}[*] Running %d ICMP scan(s) against %s with a packet interval of %4.1fs and a timeout of %ds".format(N) % (self.count, self.target, self.pktinterval, self.timeout))
        try:
            for i in range(self.count):
                if i > 0:
                    time.sleep(self.pktinterval)
                ans = sr1(IP(dst=self.target)/ICMP(), timeout=self.timeout, verbose=0)
                if ans:
                    for r in ans:
                        if ICMP in r:
                            ip_tgt = r[IP].src
                            print("{0}[*] {1} is alive!".format(G, ip_tgt))
                            if ip_tgt not in self.active_hosts:
                                self.active_hosts.append(ip_tgt)
                else:
                    print("{0}[*] Target(s) did not respond to ICMP.".format(R))
                    return False
            else:
                print("{0}[*] Target(s) responded to ICMP".format(G))
                return self.active_hosts

        except KeyboardInterrupt:
            print("{0}[*] ICMP Scan cancelled by user.".format(R))
            return False

