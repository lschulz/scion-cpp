from unittest import TestSuite
from .idint_traceroute import IdIntTraceroute


def test_suite(build_dir):
    suite = TestSuite()
    suite.addTest(IdIntTraceroute("test_peering_path", build_dir))
    suite.addTest(IdIntTraceroute("test_encrypted", build_dir))
    suite.addTest(IdIntTraceroute("test_aggregation", build_dir))
    return suite
