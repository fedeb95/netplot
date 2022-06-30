import unittest
from unittest.mock import patch, MagicMock

from scapy.sendrecv import sniff

from netplot.processor.host_processor import HostProcessor
from netplot.provider.DomainProvider import DomainProvider


class MyTestCase(unittest.TestCase):
    @patch('config.config.Config')
    def test_tcp_incoming_arg_incoming_True(self, config):
        packets = sniff(offline='./test/packets/tcp_incoming.pcap')
        config.incoming = True
        provider = DomainProvider(config)
        provider.get_domain = MagicMock(return_value='fake.domain')
        processor = HostProcessor(config, provider)

        processor.process(packets[0])

        provider.get_domain.assert_called_with('208.80.154.224')
        self.assertEqual(['fake.domain'], processor.data)

    @patch('config.config.Config')
    def test_tcp_outgoing_arg_incoming_False(self, config):
        packets = sniff(offline='./test/packets/tcp_outgoing.pcap')
        config.incoming = False
        provider = DomainProvider(config)
        provider.get_domain = MagicMock(return_value='fake.domain')
        processor = HostProcessor(config, provider)

        processor.process(packets[0])

        provider.get_domain.assert_called_with('208.80.154.224')
        self.assertEqual(['fake.domain'], processor.data)


if __name__ == '__main__':
    unittest.main()
