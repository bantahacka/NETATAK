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

# NETATAK - Windows Version
# v0.1b
# A suite of network scanning and attack tools.

#import sys
#import time
#import os
#import subprocess
import ipaddress
from atktools import *
from netscanner import *


# Define text colours
B, R, Y, G, M, N = '\33[94m', '\033[91m', '\33[93m', '\033[1;32m', '\033[1;35m', '\033[0m'


def module_installer():
    print("[*] Error: The following module is required for this program to run:")
    print("[-] scapy")
    mod_inst = input("[*] Do you wish to install it? (Y/N)".lower())
    if mod_inst in ('y', 'yes'):
        print("[*] Installing scapy, please wait...")
        subprocess.Popen("python -m pip install scapy -y", shell=True)
        sys.exit(0)


# Try and import the scapy module. If not installed, use pip to install the package
try:
    from scapy.all import *
except ImportError:
    module_installer()


def main():
    show_banner_opts()
    try:
        input_select = get_input()
        option_selector(input_select)
    except (KeyboardInterrupt, EOFError):
        print("{0}[*] Keyboard interrupt detected. Exiting program...".format(R))


def get_input():

    # Capture user input
    while True:
        capture_opt = input("{0}[*] Choose from the list above: ".format(N))
        if not capture_opt:
            continue
        try:
            capture_opt = int(capture_opt)
            if 0 < capture_opt <= 3:
                return capture_opt
            else:
                print("{0}[*] Error: Invalid option entered".format(R))
                continue
        except ValueError:
            if capture_opt == "h" or capture_opt == "help":
                print("{0}[*] Please type an option from above, press enter and follow the prompts that appear. Use CTRL+C to exit the program.".format(B))
                continue
            else:
                print("[*] Error: Invalid option entered")
                continue


def show_banner_opts():
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
    print("{0}Version: 0.1b".format(B))

    print("\r\n")
    print("{0}Available options:".format(M))
    print("""{0}
    ------
     SCAN
    ------""".format(R))
    print("{0}[1] ARP Scan".format(M))
    print("{0}[2] ICMP Scan".format(M))
    print("""{0}
    --------
     ATTACK
    --------""".format(R))
    print("{0}[3] ARP Man-In-The-Middle".format(M))
    print("""{0}
    ------
     MISC
    ------""".format(R))
    print("{0}[h] Help".format(M))
    print("\r\n")


def option_selector(opt):
    if opt == 1:
        arp_scan()
    if opt == 2:
        icmp_scan()
    if opt == 3:
        arp_mitm_start()
    if opt == 4:
        arp_mitm_stop()


def tgt_input(input_opt):
    while True:
        if input_opt == "scan":
            opt_tgt = input("{0}[*] Specify a single target (e.g. 192.168.1.10), or a range of targets using slash notation (e.g. 192.168.1.0/25): ".format(N))
            err = "{0}[*] Error: no target defined."
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


def timeout_input():
    while True:
        opt_timeout = input("{0}[*] Define a timeout for replies in seconds between 1 and 100 (e.g. 2), or leave blank for the default setting (1 second): ".format(N))
        if not opt_timeout:
            opt_timeout = 1
        try:
            opt_timeout = int(opt_timeout)
            if opt_timeout == 0:
                opt_timeout = int(1)
            if 1 > opt_timeout > 100:
                print("{0}[*] Error: timeout must be between 1 and 100 seconds.".format(R))
                continue
        except ValueError:
            print("{0}[*] Error: timeout must be a numerical value.".format(R))
            continue
        break

    return opt_timeout


def interval_input():
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


def scan_count():
    while True:
        opt_count = input("{0}[*] Define how many scans should be made against the target(s) (up to 65535), or leave blank for the default setting (1 packet): ".format(N))
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


def arp_scan():
    opt_tgt = tgt_input("scan")
    opt_timeout = timeout_input()
    opt_interval = interval_input()

    new_arp_scan = netscan_main.netscanner(1, opt_tgt, opt_timeout, opt_interval)
    new_arp_scan.init_scan()
    time.sleep(5)
    main()


def icmp_scan():
    opt_tgt = tgt_input("scan")
    opt_timeout = timeout_input()
    opt_interval = interval_input()
    opt_count = scan_count()

    new_icmp_scan = netscan_main.netscanner(2, opt_tgt, opt_timeout, opt_interval, opt_count)
    new_icmp_scan.init_scan()
    time.sleep(5)
    main()


def arp_mitm_start():
    opt_tgt = tgt_input("scan")
    opt_rtr = tgt_input("rtr")
    opt_timeout = timeout_input()
    opt_interval = interval_input()

    new_arp_mitm = arp_mitm.arp_mitm(opt_tgt, opt_rtr, 0, opt_timeout, opt_interval)
    new_arp_mitm.find_targets()
    time.sleep(5)
    main()


def arp_mitm_stop():
    opt_tgt = tgt_input("scan")
    opt_rtr = tgt_input("rtr")
    opt_timeout = timeout_input()
    opt_interval = interval_input()

    new_arp_mitm = arp_mitm.arp_mitm(opt_tgt, opt_rtr, 1, opt_timeout, opt_interval)
    new_arp_mitm.find_targets()
    time.sleep(5)
    main()


if __name__ == '__main__':
    main()