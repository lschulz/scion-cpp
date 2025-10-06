from unittest import TestSuite
from .echo_udp import UdpEcho, UdpEchoAsync
from .traceroute import Traceroute
from .path_mtu import PathMTU
from .resolver import Resolver


def test_suite(build_dir):
    suite = TestSuite()
    suite.addTest(UdpEcho("test_local", build_dir))
    suite.addTest(UdpEcho("test_remote", build_dir))
    suite.addTest(UdpEchoAsync("test_local", build_dir))
    suite.addTest(UdpEchoAsync("test_remote", build_dir))
    suite.addTest(Traceroute("test_traceroute", build_dir))
    suite.addTest(PathMTU("test_pmtu_metadata", build_dir))
    suite.addTest(PathMTU("test_pmtu_discovery", build_dir))
    suite.addTest(Resolver("test_hosts_file", build_dir))
    suite.addTest(Resolver("test_online", build_dir))
    return suite
