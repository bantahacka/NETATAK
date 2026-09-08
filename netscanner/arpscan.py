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

import threading

from scapy.all import ARP, Ether, srp
from .scan_common import (
    InterfaceResolver,
    RateLimiter,
    ScanResult,
    ScanSummary,
    TargetPlanner,
    ScanConfigurationError,
    cancellation_requested,
)

# Define text colours
B, R, Y, G, N = '\033[1;34m', '\033[1;31m', '\033[1;33m', '\033[1;32m', '\033[1;37m'

# Define the class
class ARPscanner:
    def __init__(self, target, timeout, interval, inc_mac=0, count=1,
                 verbose=1, retries=1, interface=None, cancellation=None):
        self.target = target
        self.timeout = timeout
        self.interval = interval
        self.inc_mac = inc_mac
        self.count = count
        self.verbose = verbose
        self.retries = max(1, int(retries))
        self.interface = interface
        self.cancellation = cancellation or threading.Event()

    def scan(self):
        planner = TargetPlanner(self.target)
        if planner.network.version != 4:
            raise ScanConfigurationError("ARP scanning currently supports IPv4 targets only.")
        first_target = next(planner.addresses(), planner.network.network_address)
        interface = InterfaceResolver.resolve(first_target, self.interface)
        summary = ScanSummary("ARP", self.target, interface)
        limiter = RateLimiter(self.interval)
        responses = {}

        if self.verbose:
            print("{0}[*] Running {1} ARP scan(s) against {2}; timeout={3}s, interface={4}".format(
                N, self.count, self.target, self.timeout, interface or "automatic"
            ))

        try:
            scan_rounds = max(self.count, self.retries)
            for scan_number in range(scan_rounds):
                if cancellation_requested(self.cancellation):
                    return summary.finish(cancelled=True)
                if scan_number and limiter.wait(self.cancellation):
                    return summary.finish(cancelled=True)
                kwargs = {
                    "verbose": 0,
                    "inter": 0,
                    "timeout": self.timeout,
                }
                if interface:
                    kwargs["iface"] = interface
                try:
                    answered, unanswered = srp(
                        Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=self.target),
                        **kwargs
                    )
                except Exception as error:
                    summary.add(ScanResult(
                        str(self.target),
                        "error",
                        interface=interface,
                        attempts=scan_rounds,
                        error=str(error),
                    ), sent=1)
                    return summary.finish()
                summary.sent += 1
                for sent, received in answered:
                    ip_address = received.sprintf(r"%ARP.psrc%")
                    mac_address = received.sprintf(r"%Ether.src%")
                    responses[ip_address] = mac_address
                    if self.verbose:
                        print("{0}[*] {1} responded to ARP request.".format(G, ip_address))
            if responses:
                for ip_address, mac_address in sorted(responses.items()):
                    summary.add(ScanResult(
                        ip_address,
                        "alive",
                        mac=mac_address,
                        interface=interface,
                        attempts=scan_rounds,
                    ), sent=0)
            else:
                summary.add(ScanResult(
                    str(self.target),
                    "no_response",
                    interface=interface,
                    attempts=scan_rounds,
                ), sent=0)
            return summary.finish()
        except KeyboardInterrupt:
            return summary.finish(cancelled=True)

    def arpscan(self):
        """Return the legacy ARP result shape used by the MITM module."""
        summary = self.scan()
        if summary.cancelled:
            return False
        if not summary.received:
            if self.verbose:
                print("{0}[*] No targets found via ARP.".format(R))
            return False
        if self.inc_mac:
            return {
                index: "{0}-{1}".format(result.address, result.mac)
                for index, result in enumerate(summary.results, 1)
                if result.status == "alive"
            }
        return True

