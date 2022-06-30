from scapy.all import conf

class Config:
    def __init__(self, args):
        self.iface = args.iface
        if not self.iface:
            self.iface = conf.iface
        self.verbose = args.verbose
        self.collect_hosts = args.collect_hosts
        self.filename = args.filename
        self.verbose_extra = args.verbose_extra
        self.show_missed = args.show_missed
        self.raw = args.raw
        self.show_port = args.show_port
        self.flt = args.flt
        self.both = args.both
        self.incoming = args.incoming
        self.no_analysis = args.no_analysis
