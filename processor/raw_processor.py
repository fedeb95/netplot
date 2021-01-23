from scapy.all import IP

from processor.processor import Processor


class RawProcessor(Processor):
    def __init__(self, config):
        self.config = config
        self.data = []

    def process(self, packet):
        if self.config.incoming:
            ip = packet[IP].src
        else:
            ip = packet[IP].dst
        self.data.append(ip)
