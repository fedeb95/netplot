# netplot

Ever been in one of this situations?

* "mmh... how was that `netstat` argument to show which processes are accessing the network? Let's ask StackOverflow"

* "man, I'd really want a plot in the terminal of which programs accessed the network while I was sleeping!"

* "I'd give anything for a plot in the terminal of something"

Then `netplot` is for you!

Functionalities:

* count how many TCP or UDP packets your running programs made over a period of time, and display them graphically
* optionally show which IP addresses your running programs contacted or try to resolve their dns
* find out that somehow you're selling your data to Google, Facebook & friends!

## Install
* clone this repo & run `cd netplot`
* run `python3 -m venv venv`
* run `source venv/bin/activate`
* run `pip3 install -r requirements.txt`
* start plotting against tech giants with `sudo ./venv/bin/ptyhon3 netplot.py`!

If you get:

`No data to show :-)`

then great! It means that no packets where sniffed. If you want something plotted, try opening a browser at your URL of choice.

## Options
```
usage: netplot.py [-h] [-i IFACE] [-v] [-vv] [-d] [-r] [-f FILENAME] [-m]

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
```

## TODO list
* yet to introduce great terminal plotting with [termplotlib](https://github.com/nschloe/termplotlib)
* add arguments to better control program's behaviour
* refactor some ugly stuff
* optionally store interactively captured pcap
* support more protocols beyond TCP and UDP

## Contributing
Basically any input is welcome, bugs, feature request or pull request
