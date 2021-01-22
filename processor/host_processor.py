from scapy.all import IP
import socket

from processor.processor import Processor

class HostProcessor(Processor):
    def __init__(self, config):
        self.config = config
        self.data = []

    def process(self, packet):
        if self.config.incoming:
            ip = packet[IP].src
        else:
            ip = packet[IP].dst
        self.data.append(self.get_domain(ip))

    def get_domain(self, host):
        try:
            name = socket.gethostbyaddr(host)[0]
            if self.config.verbose_extra:
                print(f"Resolving host {host} to hostname {name}")
            return name
        except socket.herror:
            if self.config.verbose_extra:
                print(f"Failure resolving {host}")
            return host


