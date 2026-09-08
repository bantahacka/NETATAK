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
# v0.7b
# A suite of network scanning and attack tools.

import sys
import os
import ctypes
import subprocess
import ipaddress
import platform
from pathlib import Path

# Define text colours
B, R, Y, G, N = '\033[1;34m', '\033[1;31m', '\033[1;33m', '\033[1;32m', '\033[1;37m'

class netatak:
    def __init__(self):
        self.scan_options = {
            "1": "ARP Scan",
            "2": "ICMP Scan",
            }
        self.attack_options = {
            "3": "ARP Man-In-The-Middle",
            "4": "DNS Spoofer"
            }
        self.misc_options = {
            "h": "Help",
            "s": "Scan settings",
            "q": "Quit",
            }
        self.selected_option = 0
        self.is_admin = False
        self.is_windows = False
        self.is_linux = False
        self.arp_scanner = None
        self.icmp_scanner = None
        self.arp_mitm = None
        self.dnspoof = None
        self.scan_settings = {
            "interface": None,
            "retries": 1,
            "output": "text",
            "csv_path": None,
        }

    def check_admin(self):
        self.is_windows = platform.system().lower() == "windows"
        if self.is_windows:
            self.is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            self.is_admin = hasattr(os, "geteuid") and os.geteuid() == 0

        if not self.is_admin:
            print("{0}[*] Error: NETATAK must be run from an elevated administrator terminal.".format(R))
            return False
        return True

    def module_importer(self):
        try:
            import scapy.all
        except (ModuleNotFoundError, ImportError):
            # Function to install scapy
            print("{0}[*] Error: The following module is required for this program to run:".format(Y))
            print("{0}[-] scapy".format(R))
            mod_inst = input("{0}[*] Do you wish to install it? (Y/N)".lower().format(Y))
            if mod_inst in ('y', 'yes'):
                print("{0}[*] If the install of Scapy fails, ensure pip is installed.".format(Y))
                print("{0}[*] Installing Scapy...".format(B))
                result = subprocess.run([sys.executable, "-m", "pip", "install", "scapy"], check=False)
                if result.returncode != 0:
                    print("{0}[*] Scapy installation failed. Install it with: {1} -m pip install scapy".format(R, sys.executable))
                    return False
                print("{0}[*] Please restart NETATAK.".format(R))
            else:
                print("{0}[*] Scapy is required to run NETATAK.".format(R))
            return False
        try:
            from netscanner.arpscan import ARPscanner
            from netscanner.icmpscan import ICMPscanner
            self.arp_scanner = ARPscanner
            self.icmp_scanner = ICMPscanner
        except (ModuleNotFoundError, ImportError):
            print("{0}[*] Error: the netscanner package is missing or incomplete.".format(R))
            return False
        try:
            from atktools import arp_mitm, dnspoof
            self.arp_mitm = arp_mitm
            self.dnspoof = dnspoof
        except (ModuleNotFoundError, ImportError):
            print("{0}[*] Error: the atktools package is missing or incomplete.".format(R))
            return False
        return True

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
        print("{0}Version: 0.7b".format(B))

        print("\r\n")
        print("{0}Available options:".format(N))
        print("""{0}
        ------
         SCAN
        ------""".format(R))
        for k, v in self.scan_options.items():
            print("{0}[{1}] {2}".format(G, k, v))
        print("""{0}
        --------
         ATTACK
        --------""".format(R))
        for k, v in self.attack_options.items():
            print("{0}[{1}] {2}".format(G, k, v))
        print("""{0}
        ------
         MISC
        ------""".format(R))
        for k, v in self.misc_options.items():
            print("{0}[{1}] {2}".format(G, k, v))
        print("\r\n")

    def get_input(self):
        while True:
            capture_opt = input("{0}[*] Choose from the list above: ".format(N)).strip().lower()
            if capture_opt == "help":
                capture_opt = "h"
            if not capture_opt:
                continue
            valid_options = set(self.scan_options) | set(self.attack_options) | set(self.misc_options)
            if capture_opt in valid_options:
                return capture_opt
            print("{0}[*] Error: Invalid option entered".format(R))

    def option_selector(self, opt):
        if opt == "1":
            return self.arp_scan()
        if opt == "2":
            return self.icmp_scan()
        if opt == "3":
            if self.is_windows:
                print("{0}[*] ARP MITM is not supported on Windows. Use a Linux host for this tool.".format(R))
                return False
            return self.arp_mitm_start()
        if opt == "4":
            if self.is_windows:
                print("{0}[*] DNS spoofing is not supported on Windows because it depends on the Linux ARP MITM implementation.".format(R))
                return False
            return self.dnspoof_start()
        if opt == "h":
            print("{0}[*] Select an option from the menu, or press CTRL+C to exit.".format(B))
            return True
        if opt == "s":
            self.configure_scan_settings()
            return True
        return False

    def configure_scan_settings(self):
        print("{0}[*] Current interface: {1}".format(N, self.scan_settings["interface"] or "automatic"))
        interface = input("{0}[*] Interface name/path, or blank for automatic selection: ".format(N)).strip()
        self.scan_settings["interface"] = interface or None
        while True:
            retries = input("{0}[*] Attempts per ICMP target (1-5, default 1): ".format(N)).strip()
            try:
                retries = int(retries) if retries else 1
                if 1 <= retries <= 5:
                    self.scan_settings["retries"] = retries
                    break
            except ValueError:
                pass
            print("{0}[*] Retries must be a number between 1 and 5.".format(R))
        while True:
            output = input("{0}[*] Output format (text/json/csv, default text): ".format(N)).strip().lower() or "text"
            if output in ("text", "json", "csv"):
                self.scan_settings["output"] = output
                break
            print("{0}[*] Choose text, json, or csv.".format(R))
        if self.scan_settings["output"] == "csv":
            path = input("{0}[*] CSV output path: ".format(N)).strip()
            self.scan_settings["csv_path"] = path or "netatak-scan.csv"
        else:
            self.scan_settings["csv_path"] = None
        print("{0}[*] Scan settings updated.".format(G))

    def display_scan_summary(self, summary):
        if self.scan_settings["output"] == "json":
            print(summary.to_json())
        elif self.scan_settings["output"] == "csv":
            summary.write_csv(self.scan_settings["csv_path"])
            print("{0}[*] Scan results written to {1}".format(G, self.scan_settings["csv_path"]))
        else:
            print("{0}[*] {1}".format(G, summary.format_text()))

    def tgt_input(self, input_opt):
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
                err = "{0}[*] Error: no target defined."
            elif input_opt == "rtr":
                opt_tgt = input("{0}[*] Specify the default gateway used by the targets (e.g. 192.168.1.1): ".format(N))
                err = "{0}[*] Error: no default gateway defined."
            else:
                raise ValueError("Unsupported target input type: {0}".format(input_opt))

            if not opt_tgt:
                print(err.format(R))
                continue
            try:
                ipaddress.ip_address(opt_tgt)
                break
            except ValueError:
                if input_opt == "scan":
                    try:
                        ipaddress.ip_network(opt_tgt, strict=False)
                        break
                    except ValueError:
                        pass
                print("{0}[*] Error: invalid target defined.".format(R))

        return opt_tgt

    def timeout_input(self, scantype):
        # Function to capture packet timeout input
        while True:
            if scantype == "arp":
                timeoutRange = "10 and 100" 
                timeoutDefault = 10
            else:
                timeoutRange = "1 and 100"
                timeoutDefault = 1
            opt_timeout = input("{0}[*] Define a timeout for replies in seconds between {1} (e.g. 2), \
            or leave blank for the default setting ({2} seconds): ".format(N, timeoutRange, timeoutDefault)).strip()
            try:
                opt_timeout = int(opt_timeout) if opt_timeout else timeoutDefault
                if scantype == "arp":
                    if not 10 <= opt_timeout <= 100:
                        print("{0}[*] Error: timeout must be between 10 and 100 seconds.".format(R))
                        continue
                elif not 1 <= opt_timeout <= 100:
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
            intervalDefault = 0.1
            opt_interval = input("{0}[*] Define an interval between packets in seconds between 0.1 and 50 (e.g. 0.4, 1), or leave blank for the default setting (0.1 second): ".format(N)).strip()
            try:
                opt_interval = float(opt_interval) if opt_interval else intervalDefault
                if not 0.1 <= opt_interval <= 50:
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
            countDefault = 1
            opt_count = input(
                "{0}[*] Define how many scans should be made against the target(s) (up to 65535), or leave blank for the default setting (1 packet): ".format(
                    N)).strip()
            try:
                opt_count = int(opt_count) if opt_count else countDefault
                if not 1 <= opt_count <= 65535:
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

        summary = self.arp_scanner(
            opt_tgt,
            opt_timeout,
            opt_interval,
            inc_mac=0,
            count=opt_count,
            verbose=1,
            retries=self.scan_settings["retries"],
            interface=self.scan_settings["interface"],
        ).scan()
        self.display_scan_summary(summary)
        return summary

    def icmp_scan(self):
        # Start ICMP scan tool
        opt_tgt = self.tgt_input("scan")
        opt_timeout = self.timeout_input("icmp")
        opt_interval = self.interval_input()
        opt_count = self.scan_count()

        summary = self.icmp_scanner(
            opt_tgt,
            opt_count,
            opt_timeout,
            opt_interval,
            verbose=1,
            retries=self.scan_settings["retries"],
            interface=self.scan_settings["interface"],
        ).scan()
        self.display_scan_summary(summary)
        return summary

    def arp_mitm_start(self):
        # Start ARP MITM tool
        opt_tgt = self.tgt_input("atk")
        opt_rtr = self.tgt_input("rtr")
        opt_timeout = self.timeout_input("arp")
        opt_interval = self.interval_input()

        return self.arp_mitm.arp_mitm(opt_tgt, opt_rtr, 0, opt_timeout, opt_interval).find_targets()

    def dnspoof_start(self):
        # Start the DNS Spoofing tool
        list_path = Path(__file__).resolve().parent / "atktools" / "config" / "dnspoof" / "spooflist.csv"
        print("{0}[*] Ensure the target sites are updated in the CSV file located at %s. If they are not, update the list and re-run this tool. List is in the format: target_domain,ip_to_reply_with e.g. www.google.com,192.168.1.100".format(Y) % list_path)
        opt_tgt = self.tgt_input("atk")
        opt_rtr = self.tgt_input("rtr")
        opt_timeout = self.timeout_input("arp")
        opt_interval = self.interval_input()

        return self.dnspoof.dnspoof(opt_tgt, opt_rtr, 0, opt_timeout, opt_interval).start_spoofer()

    def main(self):
        try:
            if not self.check_admin():
                return
            if not self.module_importer():
                return
            while True:
                self.show_banner_opts()
                option = self.get_input()
                if option == "q":
                    return
                self.option_selector(option)
        except (KeyboardInterrupt, EOFError):
            print("\n{0}[*] Keyboard interrupt detected. Exiting program...".format(R))
        except ValueError as error:
            print("{0}[*] Scan configuration error: {1}".format(R, error))

if __name__ == "__main__":
    NetAtak = netatak()
    NetAtak.main()
    