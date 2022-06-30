import psutil
from scapy.all import IP

from processor.processor import Processor


class ProcessProcessor(Processor):
    def __init__(self, config):
        self.config = config
        self.data = []

    def process(self, packet):
        if self.config.incoming:
            ip = packet[IP].src
            port = packet[IP].dport
        else:
            ip = packet[IP].dst
            port = packet[IP].sport
        connections = psutil.net_connections()
        pid = list(filter(lambda item: filter_conn(item, ip, port), connections))
        if self.config.verbose_extra:
            print("PID info: " + str(pid))
        # pids should only listen on one port at a time... or not?
        if len(pid) > 0 and len(pid[0]) > 6:
            pname = psutil.Process(pid[0][6]).name()
            if self.config.show_port:
                port = str(pid[0].laddr.port)
                pidd = str(pid[0].pid)
                pname += f" PID:{pidd} PORT:{port}"
        else:
            pname = f"unknown call to {ip}"
        self.data.append(pname)
        if self.config.verbose or self.config.verbose_extra:
            print("Process " + pname)


def filter_conn(item, ip, port):
    return has_remote_addr(item) and has_local_addr(item) and item.raddr.ip == ip and item.laddr.port == port


def has_remote_addr(item):
    return hasattr(item, 'raddr') and hasattr(item.raddr, 'ip')


def has_local_addr(item):
    return hasattr(item, 'laddr') and hasattr(item.laddr, 'port')
