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

# Netscan Module
# This file handles all network scan requests for the NETATAK suite of tools.

from .arpscan import *
from .icmpscan import *


# Define the class
class netscanner:
    def __init__(self, scantype, target, timeout, pktintr, count=1, inc_mac=0, verbose=1):
        self.scantype = scantype
        self.target = target
        self.count = count
        self.timeout = timeout
        self.pktintr = pktintr
        self.inc_mac = inc_mac
        self.verbose = verbose

    def init_scan(self):
        # This function invokes the required scan when netscanner is called
        if self.scantype == 1:
            newARPScan = ARPscanner(self.target, self.timeout, self.pktintr, self.inc_mac, self.count, self.verbose)
            tgt_list = newARPScan.arpscan()
            return tgt_list
        elif self.scantype == 2:
            newICMPScan = ICMPscanner(self.target, self.count, self.timeout, self.pktintr)
            newICMPScan.icmpscan()
