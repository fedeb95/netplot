from scapy.all import IP
import socket

from netplot.processor.processor import Processor


class HostProcessor(Processor):
    def __init__(self, config, domain_provider):
        self.config = config
        self.data = []
        self.domain_provider = domain_provider

    def process(self, packet):
        if self.config.incoming:
            ip = packet[IP].src
        else:
            ip = packet[IP].dst
        self.data.append(self.domain_provider.get_domain(ip))


