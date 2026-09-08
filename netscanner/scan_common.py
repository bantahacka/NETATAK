"""Shared defensive scanning utilities compatible with Python 3.5+."""

import csv
import ipaddress
import json
import time

from scapy.all import conf, get_if_list


class ScanConfigurationError(ValueError):
    """Raised when scan settings cannot be used safely."""


class ScanResult:
    def __init__(self, address, status, latency=None, mac=None,
                 interface=None, attempts=0, error=None):
        self.address = str(address)
        self.status = status
        self.latency = latency
        self.mac = mac
        self.interface = interface
        self.attempts = attempts
        self.error = error

    def to_dict(self):
        return {
            "address": self.address,
            "status": self.status,
            "latency": self.latency,
            "mac": self.mac,
            "interface": self.interface,
            "attempts": self.attempts,
            "error": self.error,
        }


class ScanSummary:
    def __init__(self, scan_type, target, interface=None):
        self.scan_type = scan_type
        self.target = str(target)
        self.interface = interface
        self.started_at = time.time()
        self.finished_at = None
        self.cancelled = False
        self.sent = 0
        self.results = []

    @property
    def received(self):
        return len([result for result in self.results if result.status == "alive"])

    @property
    def responded(self):
        return len([result for result in self.results if result.status != "no_response"])

    @property
    def status_counts(self):
        counts = {}
        for result in self.results:
            counts[result.status] = counts.get(result.status, 0) + 1
        return counts

    @property
    def duration(self):
        end = self.finished_at if self.finished_at is not None else time.time()
        return end - self.started_at

    def add(self, result, sent=1):
        self.results.append(result)
        self.sent += sent

    def finish(self, cancelled=False):
        self.cancelled = cancelled
        self.finished_at = time.time()
        return self

    def to_dict(self):
        return {
            "scan_type": self.scan_type,
            "target": self.target,
            "interface": self.interface,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "duration": self.duration,
            "cancelled": self.cancelled,
            "sent": self.sent,
            "received": self.received,
            "responded": self.responded,
            "status_counts": self.status_counts,
            "results": [result.to_dict() for result in self.results],
        }

    def to_json(self):
        return json.dumps(self.to_dict(), indent=2, sort_keys=True)

    def format_text(self):
        return (
            "{0} scan: {1} alive, {2} packets sent, {3:.2f}s, interface={4}, "
            "cancelled={5}".format(
                self.scan_type,
                self.received,
                self.sent,
                self.duration,
                self.interface or "automatic",
                self.cancelled,
            )
        )

    def write_csv(self, path):
        fields = ["address", "status", "latency", "mac", "interface", "attempts", "error"]
        with open(path, "w", newline="") as output:
            writer = csv.DictWriter(output, fieldnames=fields)
            writer.writeheader()
            for result in self.results:
                writer.writerow(result.to_dict())


class TargetPlanner:
    def __init__(self, target, max_targets=65536):
        self.network = self._parse(target)
        self.max_targets = max_targets
        if self.network.num_addresses > max_targets:
            raise ScanConfigurationError(
                "Target contains {0} addresses; maximum is {1}.".format(
                    self.network.num_addresses, max_targets
                )
            )

    @staticmethod
    def _parse(target):
        try:
            return ipaddress.ip_network(target, strict=False)
        except ValueError as error:
            raise ScanConfigurationError("Invalid IP target: {0}".format(error))

    def addresses(self):
        for address in self.network:
            if self.network.prefixlen < self.network.max_prefixlen:
                if address in (self.network.network_address, self.network.broadcast_address):
                    continue
            yield address


class InterfaceResolver:
    @staticmethod
    def resolve(target, interface=None):
        if interface:
            if interface not in get_if_list():
                raise ScanConfigurationError(
                    "Interface not found: {0}".format(interface)
                )
            return interface
        route = conf.route.route(str(target))
        if route and route[0]:
            return route[0]
        return None


class RateLimiter:
    def __init__(self, interval):
        self.interval = max(0.0, float(interval))
        self.next_send = None

    def wait(self, cancellation=None):
        now = time.monotonic()
        if self.next_send is None:
            self.next_send = now
            return False
        delay = self.next_send - now
        while delay > 0:
            if cancellation is not None and cancellation.is_set():
                return True
            time.sleep(min(delay, 0.05))
            now = time.monotonic()
            delay = self.next_send - now
        self.next_send = max(self.next_send + self.interval, now)
        return False


def cancellation_requested(cancellation):
    return cancellation is not None and cancellation.is_set()
