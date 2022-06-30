# netplot
[![Build Status](https://travis-ci.org/fedeb95/netplot.png?branch=master)](https://travis-ci.org/fedeb95/netplot)
[![Coverage](https://codecov.io/gh/fedeb95/netplot/branch/master/graph/badge.svg)](https://codecov.io/fedeb95/netplot/)

Ever been in one of this situations?

* "mmh... how was that `netstat` argument to show which processes are accessing the network? Let's ask StackOverflow"

* "man, I'd really want a plot in the terminal of which programs accessed the network while I was sleeping!"

* "I'd give anything for a plot in the terminal of something"

Then `netplot` is for you!

Functionalities:

* count how many packets your running programs sent over a period of time, and display them graphically
* optionally show which IP addresses your running programs contacted or try to resolve their dns
* find out that somehow you're selling your data to Google, Facebook & friends!

## Example

```
(venv) fedeb@debian:~/Projects/netplot$ sudo venv/bin/python3 netplot -i wlp2s0
Sniffing packets, interrupt with Ctrl+C
^C
unknown call to dns.adguard.com  [220]  ****************************************
firefox-esr                      [ 45]  *********
evolution-calendar-factory       [  6]  **
vivaldi-bin                      [  2]  *
```

## Install
clone this repo & run:
```
> cd netplot
> sudo python -m pip install .
```
Congratulations, you can start plotting against tech giants with `sudo netplot`!

If you get:

`No data to show :-)`

then great! It means that no packets where sent by your computer, so reasonably you don't have trackers around. If you want something plotted, try opening a browser at your URL of choice.

## Usage
```
usage: netplot [-h] [-i IFACE] [-v] [-vv] [-d] [-r] [-f FILENAME] [-m] [-p]
               [-F FLT] [-x] [-b] [-n]

netplot - plots programs accessing the network

optional arguments:
  -h, --help            show this help message and exit
  -i IFACE, --iface IFACE
                        Interface to use, default is scapy's default interface
  -v, --verbose         Verbose output for each processed packet
  -vv, --verbose-extra  Extra verbose output for each processed packet
  -d, --resolve-domain  Resolve domains called instead of processes
  -r, --raw             Disable both domain and process resolution
  -f FILENAME, --file FILENAME
                        Read packets from input file instead of directly
                        accessing network
  -m, --missed          Show not supported protocols as missed packets
  -p, --show-port       Show which port each process is listening on and its
                        PID. Not compatible with -r and -d
  -F FLT, --filter FLT  Filter in BPF syntax (same as scapy)
  -x, --incoming        Process incoming packets instead of outgoing
  -b, --both            Process both incoming and outgoing packets
  -n, --no-analysis     Don't plot anything, just display collected entries
                        (ideal for further processing). This ignores -m
```

Since apparently `scapy` is slow and misses packets, for some use cases it's better to run `tcpdump` and then process a file with `netplot`.
This can be done with the simple `netplot.sh` wrapper:

```
./netplot.sh <network_interface> <filename> <other_netplot_args>
```
This has the drawback of potentially missing process names, so if you need them just stick to `netplot.py` without the `-f` option.

## Further output processing

If you don't care about plots but want to further process data collected by `netplot`, run it with the `--no-analysis` option.
This way processes, domains or hosts as set with the other parameters are simply gathered and printed on a newline each.

An example of further processing can be found in `whois-report.sh` that given an interface listens on it with `tcpdump`,
then runs `netplot` for hosts and finally generates a report.txt with a `whois` query for each host found. It also saves
addresses in addresses.txt and packets in packets.pcap. You can see a quick summary of organizations with

```
cat report.txt | grep OrgTechName | sort | uniq
```

## Mitm
If you use netplot.sh while doing a mitm attack (maybe with `arpspoof`) you can see which sites where most visited by target host in your network. Since process resolution doesn't make sense, `netplot` is best used with `--resolve-domain` or `--raw`.

## TODO list
* add arguments to better control program's behaviour
* refactor some ugly stuff
* optionally store interactively captured pcap
* support more protocols beyond TCP and UDP
* more plots

## Contributing
Basically any input is welcome, bugs, feature request or pull request
