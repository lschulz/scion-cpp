#!/bin/env python
# Copyright (c) 2026 Lars-Christian Schulz
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import argparse
import subprocess
import unittest
from pathlib import Path


class TestCLI(unittest.TestCase):
    """Test command line parsing"""
    def __init__(self, methodName, build_dir):
        super().__init__(methodName)
        self.scitra_tun = Path(build_dir) / "scitra/Debug/scitra-tun-d"

    def test_help(self):
        res = subprocess.run([
            self.scitra_tun, "-h"
        ], capture_output=True)
        self.assertEqual(res.returncode, 0)
        self.assertIn("scitra-tun: Userspace SCION-IP Translator", res.stdout.decode())
        self.assertEqual(res.stderr.decode(), "")

    def test_version(self):
        res = subprocess.run([
            self.scitra_tun, "-v"
        ], capture_output=True)
        self.assertEqual(res.returncode, 0)
        self.assertRegex(res.stdout.decode(), "Scitra-TUN [0-9]+.[0-9]+.[0-9]+(-.+)?")
        self.assertEqual(res.stderr.decode(), "")

    def test_extra_args(self):
        res = subprocess.run([
            self.scitra_tun, "-a=127.0.0.1", "-p", "1,2", "3"
        ], capture_output=True)
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("The following argument was not expected: 3", res.stderr.decode())
        res = subprocess.run([
            self.scitra_tun, "-a=127.0.0.1", "-e", "127.0.0.2,127.0.0.3", "127.0.0.4"
        ], capture_output=True)
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("The following argument was not expected: 127.0.0.4", res.stderr.decode())


def suite(build_dir):
    suite = unittest.TestSuite()
    suite.addTest(TestCLI("test_help", build_dir))
    suite.addTest(TestCLI("test_version", build_dir))
    suite.addTest(TestCLI("test_extra_args", build_dir))
    return suite


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Test Scitra-TUN CLI")
    parser.add_argument("-b", "--build", type=Path, default="build",
        help="Path to CMake build directory")
    args = parser.parse_args()

    runner = unittest.TextTestRunner()
    runner.run(suite(args.build))
