# Copyright (c) 2024-2025 Lars-Christian Schulz
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

import subprocess
import time
import unittest
from pathlib import Path
from subprocess import DEVNULL, PIPE


class PathMTU(unittest.TestCase):
    def __init__(self, methodName, build_dir="build"):
        super().__init__(methodName)
        self.command_server = Path(build_dir) / "examples/Debug/echo-udp-async"
        self.command = Path(build_dir) / "examples/Debug/pmtu"

    def setUp(self):
        self.server = subprocess.Popen([
            self.command_server,
            "--sciond", "127.0.0.27:30255",
            "--local", "127.0.0.1:32000"
        ], stdout=DEVNULL)
        time.sleep(0.2)

    def tearDown(self):
        self.server.terminate()
        self.server.wait()

    def test_pmtu_metadata(self):
        """PMTU discovery starts with MTU from path metadata"""
        self.assertIsNone(self.server.poll())
        res = subprocess.run([
            self.command,
            "--sciond", "127.0.0.19:30255",
            "--local", "127.0.0.1",
            "1-ff00:0:112,127.0.0.1:32000"
        ], stdout=PIPE, check=True)
        self.assertEqual(res.stdout.decode(),
            "Try PMTU = 1280\n"
            "Found PMTU = 1280\n")

    def test_pmtu_discovery(self):
        """Ignore path metadata and start with a PMTU of 9000 bytes"""
        self.assertIsNone(self.server.poll())
        res = subprocess.run([
            self.command,
            "--sciond", "127.0.0.19:30255",
            "--local", "127.0.0.1",
            "--mtu", "9000",
            "1-ff00:0:112,127.0.0.1:32000"
        ], stdout=PIPE, check=True)
        self.assertEqual(res.stdout.decode(),
            "Try PMTU = 9000\n"
            "Try PMTU = 1280\n"
            "Found PMTU = 1280\n")
