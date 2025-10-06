from unittest import TestSuite
from .echo_udp import UdpEcho, UdpEchoAsync


def test_suite(build_dir):
    suite = TestSuite()
    suite.addTest(UdpEcho("test_local", build_dir))
    suite.addTest(UdpEcho("test_remote", build_dir))
    suite.addTest(UdpEchoAsync("test_local", build_dir))
    suite.addTest(UdpEchoAsync("test_remote", build_dir))
    return suite
