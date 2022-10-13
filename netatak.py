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

# NETATAK
# v0.5b
# A suite of network scanning and attack tools.

import sys
import time
import os
import subprocess
import ipaddress
import platform

# Define text colours
B, R, Y, G, N = '\033[1;34m', '\033[1;31m', '\033[1;33m', '\033[1;32m', '\033[1;37m'

#Check to see if user is running as root
if os.geteuid() != 0:
    print("{0}[*] Error: You must run this script using sudo or as root. Exiting...".format(R))
    sys.exit()

def module_installer():
    # Function to install scapy
    print("{0}[*] Error: The following module is required for this program to run:".format(Y))
    print("{0}[-] scapy".format(R))
    mod_inst = input("{0}[*] Do you wish to install it? (Y/N)".lower().format(Y))
    if mod_inst in ('y', 'yes'):
        print("{0}[*] If the install of Scapy fails, ensure you have the python3-pip package or pip module installed.")
        print("{0}[*] Installing scapy, going to sleep for 30 seconds...".format(B))
        subprocess.Popen("python3 -m pip install scapy", shell=True)
        time.sleep(30)
        print("{0}[*] Please restart NETATAK.".format(R))
        sys.exit()


# Try and import scapy. If not installed, use pip to install the package
try:
    from scapy.all import *
except (ModuleNotFoundError, ImportError):
    module_installer()

from atktools import arp_mitm, dnspoof
from netscanner import netscan_main

class netatak:
    def get_input(self):
        # Capture user input
        while True:
            capture_opt = input("{0}[*] Choose from the list above: ".format(N))
            if not capture_opt:
                continue
            try:
                capture_opt = int(capture_opt)
                if 0 < capture_opt <= 4:
                    return capture_opt
                else:
                    print("{0}[*] Error: Invalid option entered".format(R))
                    continue
            except ValueError:
                if capture_opt == "h" or capture_opt == "help":
                    print(
                        "{0}[*] Please type an option from above, press enter and follow the prompts that appear. Use CTRL+C to stop a task or to exit the program.".format(
                            B))
                    continue
                else:
                    print("{0}[*] Error: Invalid option entered".format(R))
                    continue

    def show_banner_opts(self):
        # Print the banner and show the available options
        print(r"""{0}{1}
     ________   _______  _________  ________  _________  ________  ___  __
    |\   ___  \|\  ___ \|\___   ___\\   __  \|\___   ___\\   __  \|\  \|\  \
    \ \  \\ \  \ \   __/\|___ \  \_\ \  \|\  \|___ \  \_\ \  \|\  \ \  \/  /|_
     \ \  \\ \  \ \  \_|/__  \ \  \ \ \   __  \   \ \  \ \ \   __  \ \   ___  \
      \ \  \\ \  \ \  \_|\ \  \ \  \ \ \  \ \  \   \ \  \ \ \  \ \  \ \  \\ \  \
       \ \__\\ \__\ \_______\  \ \__\ \ \__\ \__\   \ \__\ \ \__\ \__\ \__\\ \__\
        \|__| \|__|\|_______|   \|__|  \|__|\|__|    \|__|  \|__|\|__|\|__| \|__|                                                                             
    """.format(Y, N))
        print("{0}NETATAK - A suite of network scanning and attack tools.".format(B))
        print("{0}Version: 0.3b".format(B))

        print("\r\n")
        print("{0}Available options:".format(N))
        print("""{0}
        ------
         SCAN
        ------""".format(R))
        print("{0}[1] ARP Scan".format(G))
        print("{0}[2] ICMP Scan".format(G))
        print("""{0}
        --------
         ATTACK
        --------""".format(R))
        print("{0}[3] ARP Man-In-The-Middle".format(G))
        print("{0}[4] DNS Spoofer".format(G))
        print("""{0}
        ------
         MISC
        ------""".format(R))
        print("{0}[h] Help".format(G))
        print("\r\n")

    def option_selector(self, opt):
        # Run the required tool based on user input
        if opt == 1:
            self.arp_scan()
        if opt == 2:
            self.icmp_scan()
        if opt == 3:
            self.arp_mitm_start()
        if opt == 4:
            self.dnspoof_start()


    def tgt_input(self, input_opt):
        # Function to capture target input
        while True:
            if input_opt == "scan":
                opt_tgt = input(
                    "{0}[*] Specify a single target (e.g. 192.168.1.10), or a range of targets using slash notation (e.g. 192.168.1.0/25): ".format(
                        N))
                err = "{0}[*] Error: no target defined."
            elif input_opt == "atk":
                opt_tgt = input(
                    "{0}[*] Specify a single target (e.g. 192.168.1.10): ".format(
                        N))
            elif input_opt == "rtr":
                opt_tgt = input("{0}[*] Specify the default gateway used by the targets (e.g. 192.168.1.1): ".format(N))
                err = "{0}[*] Error: no default gateway defined."

            if not opt_tgt:
                print(err.format(R))
                continue
            else:
                try:
                    if ipaddress.ip_address(opt_tgt):
                        break
                except ValueError:
                    try:
                        if ipaddress.ip_network(opt_tgt):
                            break
                    except ValueError:
                        print("{0}[*] Error: invalid target defined.".format(R))
                    continue

        return opt_tgt

    def timeout_input(self, scantype):
        # Function to capture packet timeout input
        while True:
            if scantype == "arp":
                opt_timeout = input("{0}[*] Define a timeout for replies in seconds between 10 and 100 (e.g. 2), or leave blank for the default setting (10 seconds): ".format(N))
            else:
                opt_timeout = input("{0}[*] Define a timeout for replies in seconds between 1 and 100 (e.g. 2), or leave blank for the default setting (1 second): ".format(N))
            if not opt_timeout:
                if scantype == "arp":
                    opt_timeout = 10
                else:
                    opt_timeout = 1
            try:
                opt_timeout = int(opt_timeout)
                if opt_timeout == 0:
                    if scantype == "arp":
                        opt_timeout = int(10)
                    else:
                        opt_timeout = int(1)
                if scantype == "arp":
                    if 10 > opt_timeout > 100:
                        print("{0}[*] Error: timeout must be between 10 and 100 seconds.".format(R))
                        continue
                    elif 1 > opt_timeout > 100:
                        print("{0}[*] Error: timeout must be between 1 and 100 seconds.".format(R))
                        continue
            except ValueError:
                print("{0}[*] Error: timeout must be a numerical value.".format(R))
                continue
            break

        return opt_timeout

    def interval_input(self):
        # Function to capture packet interval input
        while True:
            opt_interval = input("{0}[*] Define an interval between packets in seconds between 0.1 and 50 (e.g. 0.4, 1), or leave blank for the default setting (0.1 second): ".format(N))
            if not opt_interval:
                opt_interval = 0.1
            try:
                opt_interval = float(opt_interval)
                if opt_interval == 0:
                    opt_interval = float(0.1)
                if 0.1 > opt_interval > 50:
                    print("{0}[*] Error: interval must be between 0.1 and 50 seconds.".format(R))
                    continue
            except ValueError:
                print("{0}[*] Error: interval must be a whole or decimal number.".format(R))
                continue
            break

        return opt_interval

    def scan_count(self):
        # Function to capture scan count input
        while True:
            opt_count = input(
                "{0}[*] Define how many scans should be made against the target(s) (up to 65535), or leave blank for the default setting (1 packet): ".format(
                    N))
            if not opt_count:
                opt_count = 1
            try:
                opt_count = int(opt_count)
                if opt_count == 0:
                    opt_count = int(1)
                if 1 > opt_count > 65535:
                    print("{0}[*] Error: interval must be between 1 and 65535 seconds.".format(R))
                    continue
            except ValueError:
                print("{0}[*] Error: interval must be a numerical value.".format(R))
                continue
            break

        return opt_count

    def arp_scan(self):
        # Start ARP scan tool
        opt_tgt = self.tgt_input("scan")
        opt_timeout = self.timeout_input("arp")
        opt_interval = self.interval_input()
        opt_count = self.scan_count()

        new_arp_scan = netscan_main.netscanner(1, opt_tgt, opt_timeout, opt_interval, opt_count)
        new_arp_scan.init_scan()
        time.sleep(5)
        self.main()

    def icmp_scan(self):
        # Start ICMP scan tool
        opt_tgt = self.tgt_input("scan")
        opt_timeout = self.timeout_input("icmp")
        opt_interval = self.interval_input()
        opt_count = self.scan_count()

        new_icmp_scan = netscan_main.netscanner(2, opt_tgt, opt_timeout, opt_interval, opt_count)
        new_icmp_scan.init_scan()
        time.sleep(5)
        self.main()

    def arp_mitm_start(self):
        # Start ARP MITM tool
        opt_tgt = self.tgt_input("atk")
        opt_rtr = self.tgt_input("rtr")
        opt_timeout = self.timeout_input("arp")
        opt_interval = self.interval_input()

        new_arp_mitm = arp_mitm.arp_mitm(opt_tgt, opt_rtr, 0, opt_timeout, opt_interval)
        new_arp_mitm.find_targets()
        time.sleep(5)
        self.main()

    def dnspoof_start(self):
        # Start the DNS Spoofing tool
        opt_tgt = self.tgt_input("atk")
        opt_rtr = self.tgt_input("rtr")
        opt_timeout = self.timeout_input("arp")
        opt_interval = self.interval_input()

        new_dnspoof = dnspoof.dnspoof(opt_tgt, opt_rtr, 0, opt_timeout, opt_interval)
        new_dnspoof.start_spoofer()
        time.sleep(5)
        self.main()

    def main(self):
        self.show_banner_opts()
        try:
            input_select = self.get_input()
            self.option_selector(input_select)
        except (KeyboardInterrupt, EOFError):
            print("\n{0}[*] Keyboard interrupt detected. Exiting program...".format(R))


NetAtak = netatak()
NetAtak.main()
