import unittest
from unittest.mock import patch

from scapy.all import *
from processor.raw_processor import RawProcessor


class MyTestCase(unittest.TestCase):
    @patch('config.config.Config')
    def test_tcp_incoming_arg_incoming_True(self, config):
        packets = sniff(offline='./test/packets/tcp_incoming.pcap')
        config.incoming = True
        processor = RawProcessor(config)

        processor.process(packets[0])

        self.assertEqual(['208.80.154.224'], processor.data)

    @patch('config.config.Config')
    def test_tcp_incoming_arg_incoming_False(self, config):
        """
        This case never happens because incoming packets aren't even passed to processors with incoming False
        """
        packets = sniff(offline='./test/packets/tcp_incoming.pcap')
        config.incoming = False
        processor = RawProcessor(config)

        processor.process(packets[0])

        self.assertEqual(['192.168.1.145'], processor.data)

    @patch('config.config.Config')
    def test_tcp_outgoing_arg_incoming_False(self, config):
        packets = sniff(offline='./test/packets/tcp_outgoing.pcap')
        config.incoming = False
        processor = RawProcessor(config)

        processor.process(packets[0])

        self.assertEqual(['208.80.154.224'], processor.data)

    @patch('config.config.Config')
    def test_tcp_outgoing_arg_incoming_True(self, config):
        """
        This case never happens because outgoing packets aren't even passed to processors with incoming True
        """
        packets = sniff(offline='./test/packets/tcp_outgoing.pcap')
        config.incoming = True
        processor = RawProcessor(config)

        processor.process(packets[0])

        self.assertEqual(['192.168.1.145'], processor.data)


if __name__ == '__main__':
    unittest.main()