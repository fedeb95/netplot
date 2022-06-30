import socket


class DomainProvider:
    def __init__(self, config):
        self.config = config

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
