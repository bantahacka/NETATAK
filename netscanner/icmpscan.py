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

import random
import time
import threading
from scapy.all import ICMP, IP, sr1
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
class ICMPscanner:
    def __init__(self, target, count, timeout, pktinterval, verbose=1,
                 retries=1, interface=None, cancellation=None):
        self.target = target
        self.count = count
        self.timeout = timeout
        self.interval = pktinterval
        self.verbose = verbose
        self.retries = max(1, int(retries))
        self.interface = interface
        self.cancellation = cancellation or threading.Event()

    def scan(self):
        planner = TargetPlanner(self.target)
        if planner.network.version != 4:
            raise ScanConfigurationError("ICMP scanning currently supports IPv4 targets only.")
        first_target = next(planner.addresses(), planner.network.network_address)
        interface = InterfaceResolver.resolve(first_target, self.interface)
        summary = ScanSummary("ICMP", self.target, interface)
        limiter = RateLimiter(self.interval)
        if self.verbose:
            print("{0}[*] Running {1} ICMP scan(s) against {2}; timeout={3}s, interface={4}".format(
                N, self.count, self.target, self.timeout, interface or "automatic"
            ))
        try:
            for scan_number in range(self.count):
                for target in planner.addresses():
                    if cancellation_requested(self.cancellation):
                        return summary.finish(cancelled=True)
                    if limiter.wait(self.cancellation):
                        return summary.finish(cancelled=True)
                    response = None
                    attempts = 0
                    packet_error = None
                    started = time.monotonic()
                    for attempt in range(self.retries):
                        if cancellation_requested(self.cancellation):
                            return summary.finish(cancelled=True)
                        attempts += 1
                        kwargs = {"timeout": self.timeout, "verbose": 0}
                        try:
                            response = sr1(
                                IP(dst=str(target)) / ICMP(id=random.randint(100, 1000)),
                                **kwargs
                            )
                        except Exception as error:
                            summary.add(ScanResult(
                                target,
                                "error",
                                latency=time.monotonic() - started,
                                interface=interface,
                                attempts=attempts,
                                error=str(error),
                            ), sent=1)
                            packet_error = error
                            response = None
                            break
                        summary.sent += 1
                        if response is not None:
                            break
                    if packet_error is not None:
                        continue
                    latency = time.monotonic() - started
                    status = "no_response"
                    if response is not None:
                        if response.haslayer(ICMP) and int(response.getlayer(ICMP).type) == 3:
                            status = "filtered"
                        else:
                            status = "alive"
                    result = ScanResult(
                        target,
                        status,
                        latency=latency,
                        interface=interface,
                        attempts=attempts,
                    )
                    summary.add(result, sent=0)
                    if self.verbose:
                        message = "alive" if status == "alive" else status.replace("_", " ")
                        print("{0}[*] {1}: {2}".format(G if status == "alive" else R, target, message))
            return summary.finish()
        except KeyboardInterrupt:
            return summary.finish(cancelled=True)

    def icmpscan(self):
        """Return the legacy list of responsive addresses."""
        summary = self.scan()
        if summary.cancelled:
            return False
        return [result.address for result in summary.results if result.status == "alive"]

