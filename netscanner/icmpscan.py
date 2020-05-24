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

from scapy.all import *
import ipaddress

# Define text colours
B, R, Y, G, M, N = '\33[94m', '\033[91m', '\33[93m', '\033[1;32m', '\033[1;35m', '\033[0m'

# Define the class
class ICMPscanner:
    def __init__(self, target, count, timeout, pktinterval):
        self.target = target
        self.addresses = ipaddress.IPv4Network(self.target)
        self.count = count
        self.timeout = timeout
        self.pktinterval = pktinterval
        self.active_hosts = []

    def icmpscan(self):
        # Run an ICMP scan against the target machine/network and report any hosts that are alive.
        print("{0}[*] Running %d ICMP scan(s) against %s with a packet interval of %4.1fs and a timeout of %ds".format(N) % (self.count, self.target, self.pktinterval, self.timeout))
        total_resps = 0
        total_scans = 0
        try:
            for i in range(self.count):
                total_scans = i+1
                for target in self.addresses:
                    time.sleep(self.pktinterval)
                    if target == self.addresses.network_address and "/" in self.target:
                        print("{0}[*] Ignoring Network ID: {1}".format(Y, self.addresses.network_address))
                        continue
                    if target == self.addresses.broadcast_address and "/" in self.target:
                        print("{0}[*] Ignoring Broadcast Address: {1}".format(Y, self.addresses.broadcast_address))
                        continue
                    ans = sr1(IP(dst=str(target))/ICMP(id=random.randint(100, 1000)), timeout=self.timeout, verbose=0)
                    if ans is None:
                        print("{0}[*] {1} is down or not responding".format(R, target))
                    elif int(ans.getlayer(ICMP).type) == 3 and int(ans.getlayer(ICMP).code) in [1,2,3,9,10,13]:
                        print("{0}[*] {1} is blocking ICMP".format(Y, target))
                    else:
                        print("{0}[*] {1} is alive!".format(G, target))
                        if target not in self.active_hosts:
                            self.active_hosts.append(target)
                        total_resps += 1
                else:
                    print("{0}[*] Scans completed: {1} of {2}". format(G, total_scans, self.count))
                    print("{0}[*] {1} Target(s) responded to ICMP".format(G, len(self.active_hosts)))
            return self.active_hosts


        except KeyboardInterrupt:
            print("{0}[*] ICMP Scan cancelled by user.".format(R))
            return False

