#! /usr/bin/env python3

# imports for program utilities
from signal import signal, SIGINT
from sys import exit
import argparse

# imports for net stuff
from scapy.all import *
import socket

# import for processes
import psutil

# imports for analysis
import numpy as np
import pandas as pd
import termplotlib as tpl

# arguments
iface = None
verbose = False
collect_hosts = False
filename = None
verbose_extra = False
show_missed = False
raw = False

# data collected
collected_data = []

missed = []

def get_addr_or_host(host):
    try:
        name = socket.gethostbyaddr(host)[0]
        if verbose_extra:
            print(f"Resolving host {host} to hostname {name}")
        return name
    except socket.herror:
        if verbose_extra:
            print(f"Failure resolving {host}")
        return host

def analyze_packets(signal_received, frame):
    # insert new line after Ctrl+C
    print()
    if verbose or verbose_extra:
        print("Analyzing packets")
    if collected_data == []:
        print("No data to show :-)")
    else:
        data = np.array(collected_data);
        columns = ["data"]
        df = pd.DataFrame(data=list(collected_data), columns=columns)
        table = df["data"].value_counts()
        labels = list(table.index)
        counts = [ int(c) for c in table.to_numpy().tolist() ]
        fig = tpl.figure()
        fig.barh(counts, labels, force_ascii=True)
        fig.show()
    if show_missed and len(missed) > 0:
        print()
        print("Packets not analyzed: ")
        [print(miss) for miss in missed]
    exit(0)

def sniff_packets(store=False):
    if filename:
        if verbose or verbose_extra:
            print(f"Reading packets from {filename}")
        packets = sniff(offline=filename, iface=iface)
        [ process_packet(packet) for packet in packets ]
        analyze_packets(None, None)
    else:
        signal(SIGINT, analyze_packets)
        print("Sniffing packets, interrupt with Ctrl+C")
        if iface:
            if iface:
                ip = get_if_addr(iface)
                if verbose or verbose_extra:
                    print(f"Started packed capture for {ip}");
            sniff(prn=process_packet, iface=iface, store=store)
        else:
            sniff(prn=process_packet, store=store)

def process_packet(packet):
    """
    This function is executed whenever a packet is sniffed
    """
    if (packet.haslayer(TCP) or packet.haslayer(UDP)) and packet.haslayer(IP):
        if not iface or packet[IP].dst != get_if_addr(iface):
            if verbose or verbose_extra:
                print("==============================")
                print(packet.summary())
                print("Packet src: " + packet[IP].src)
                print("Packet src port: " + str(packet[IP].sport))
                print("Packet dst: " + packet[IP].dst)
                print("Packet dst port: " + str(packet[IP].dport))
            ip = get_addr_or_host(packet[IP].dst)
            port = packet[IP].sport
            if collect_hosts:
                collected_data.append(ip)
            elif raw:
                collected_data.append(packet[IP].dst)
            else:
                connections = psutil.net_connections()
                pid = list(filter(lambda item: filter_conn(item, packet), connections))
                if verbose_extra:
                    print("PID info: " + str(pid))
                # pids should only listen on one port at a time... or not?
                if len(pid) > 0 and len(pid[0]) > 6:
                    pname = psutil.Process(pid[0][6]).name()
                else:
                    pname = f"unknown call to {ip}"
                collected_data.append(pname)
                if verbose or verbose_extra:
                    print("Process " + pname)
    else:
        missed.append("not collected: " + packet.summary())

def filter_conn(item, packet):
    return hasattr(item, 'raddr') and hasattr(item.raddr, 'ip') and hasattr(item, 'laddr') and hasattr(item.laddr, 'port') and item.raddr.ip==packet[IP].dst and item.laddr.port==packet[IP].sport

def main():
    global iface, verbose, filename, collect_hosts, verbose_extra, show_missed, raw
    parser = argparse.ArgumentParser(description="netplot - plots programs accessing the network")
    parser.add_argument("-i", "--iface", help="Interface to use, default is scapy's default interface")
    parser.add_argument("-v", "--verbose", dest="verbose", action="store_true", help="Verbose output for each processed packet")
    parser.add_argument("-vv", "--verbose-extra", dest="verbose_extra", action="store_true", help="Extra verbose output for each processed packet")
    parser.add_argument("-d", "--resolve-domain", dest="collect_hosts", action="store_true", help="Resolve domains called instead of processes")
    parser.add_argument("-r", "--raw", dest="raw", action="store_true", help="Disable both domain and process resolution")
    parser.add_argument("-f", "--file", dest="filename", action="store", help="Read packets from input file instead of directly accessing network")
    parser.add_argument("-m", "--missed", dest="show_missed", action="store_true", help="Show not supported protocols as missed packets")
    args = parser.parse_args()
    iface = args.iface
    if not iface:
        iface = conf.iface
    verbose = args.verbose
    verbose_extra = args.verbose_extra
    show_missed = args.show_missed
    collect_hosts = args.collect_hosts
    filename = args.filename
    raw = args.raw
    sniff_packets()

if __name__=='__main__':
    main()
