from unittest import TestSuite
from .test_target import UdpTestTarget
from .resolver import InterposedResolver
from .netcat import InterposedNetcat


def test_suite(build_dir):
    suite = TestSuite()
    suite.addTest(UdpTestTarget("test_local", build_dir))
    suite.addTest(UdpTestTarget("test_remote", build_dir))
    suite.addTest(InterposedResolver("test_resolver", build_dir))
    suite.addTest(InterposedNetcat("test_local", build_dir))
    suite.addTest(InterposedNetcat("test_remote", build_dir))
    return suite
