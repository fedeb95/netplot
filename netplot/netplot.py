#! /usr/bin/env python3

# imports for program utilities
from signal import signal, SIGINT
from sys import exit
import argparse

# imports for net stuff
from scapy.all import *
import socket

# imports for analysis
import numpy as np
import pandas as pd
import termplotlib as tpl

from netplot.processor.process_processor import ProcessProcessor
from netplot.processor.raw_processor import RawProcessor
from netplot.processor.host_processor import HostProcessor
from netplot.config.config import Config

# arguments
from provider.DomainProvider import DomainProvider

config = None

missed = []

processor = None


def analyze_packets(signal_received, frame):
    # insert new line after Ctrl+C
    print()
    collected_data = processor.data
    if config.no_analysis:
        [print(entry) for entry in set(collected_data)]
        exit(0)
    if config.verbose or config.verbose_extra:
        print("Analyzing packets")
    if not collected_data:
        print("No data to show :-)")
    else:
        columns = ["data"]
        df = pd.DataFrame(data=list(collected_data), columns=columns)
        table = df["data"].value_counts()
        labels = list(table.index)
        counts = [int(c) for c in table.to_numpy().tolist()]
        fig = tpl.figure()
        fig.barh(counts, labels, force_ascii=True)
        fig.show()
    if config.show_missed and len(missed) > 0:
        print()
        print("Packets not analyzed: ")
        [print(miss) for miss in missed]
    elif len(missed) > 0:
        miss_count = len(missed)
        print(f"Not showing {miss_count} unknown packets. Run with -m")
    exit(0)


def sniff_packets(store=False):
    if config.filename:
        if config.verbose or config.verbose_extra:
            print(f"Reading packets from {config.filename}")
        packets = sniff(filter=config.flt, offline=config.filename, iface=config.iface)
        [process_packet(packet) for packet in packets]
        analyze_packets(None, None)
    else:
        signal(SIGINT, analyze_packets)
        print("Sniffing packets, interrupt with Ctrl+C")
        if config.iface:
            ip = get_if_addr(config.iface)
            if config.verbose or config.verbose_extra:
                print(f"Started packed capture for {ip}");
            sniff(filter=config.flt, prn=process_packet, iface=config.iface, store=store)
        else:
            sniff(filter=config.flt, prn=process_packet, store=store)


def process_packet(packet):
    """
    This function is executed whenever a packet is sniffed
    """
    if (packet.haslayer(TCP) or packet.haslayer(UDP)) and packet.haslayer(IP):
        if is_to_process(packet, get_if_addr(config.iface)):
            if config.verbose or config.verbose_extra:
                print("==============================")
                print(packet.summary())
            processor.process(packet)
    else:
        missed.append("not collected: " + packet.summary())


def is_to_process(packet, localaddr):
    if config.both:
        # both incoming and outgoing packets
        return True
    if config.incoming:
        # incoming packets only
        return packet[IP].dst == localaddr
    else:
        # outgoing packets only
        return packet[IP].dst != localaddr


def main():
    parser = argparse.ArgumentParser(description="netplot - plots programs accessing the network")
    parser.add_argument("-i", "--iface", help="Interface to use, default is scapy's default interface")
    parser.add_argument("-v", "--verbose", dest="verbose", action="store_true",
                        help="Verbose output for each processed packet")
    parser.add_argument("-vv", "--verbose-extra", dest="verbose_extra", action="store_true",
                        help="Extra verbose output for each processed packet")
    parser.add_argument("-d", "--resolve-domain", dest="collect_hosts", action="store_true",
                        help="Resolve domains called instead of processes")
    parser.add_argument("-r", "--raw", dest="raw", action="store_true",
                        help="Disable both domain and process resolution")
    parser.add_argument("-f", "--file", dest="filename", action="store",
                        help="Read packets from input file instead of directly accessing network")
    parser.add_argument("-m", "--missed", dest="show_missed", action="store_true",
                        help="Show not supported protocols as missed packets")
    parser.add_argument("-p", "--show-port", dest="show_port", action="store_true",
                        help="Show which port each process is listening on and its PID. Not compatible with -r and -d")
    parser.add_argument("-F", "--filter", dest="flt", action="store", help="Filter in BPF syntax (same as scapy)")
    parser.add_argument("-x", "--incoming", dest="incoming", action="store_true",
                        help="Process incoming packets instead of outgoing")
    parser.add_argument("-b", "--both", dest="both", action="store_true",
                        help="Process both incoming and outgoing packets")
    parser.add_argument("-n", "--no-analysis", dest="no_analysis", action="store_true",
                        help="Don't plot anything, just display collected entries (ideal for further processing). "
                             "This ignores -m")
    args = parser.parse_args()
    global config, processor
    config = Config(args)

    if config.collect_hosts:
        processor = HostProcessor(config, DomainProvider(config))
    elif config.raw:
        processor = RawProcessor(config)
    else:
        processor = ProcessProcessor(config)

    sniff_packets()
