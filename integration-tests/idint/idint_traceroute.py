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

import subprocess
import time
import unittest
from pathlib import Path
from subprocess import DEVNULL, PIPE


EXPECTED_PEERING_PATH = """\
Source: 1-ff00:0:112,127.0.0.1:32000 Dest: [2-ff00:0:222,fd00:f00d:cafe::7f00:53]:32001
Path: 1-ff00:0:112 494>103 1-ff00:0:111 101>5 2-ff00:0:211 4>301 2-ff00:0:222

Forward:
  Flags       Source AS NodeID IgPort EgPort   ISD             ASN    DEVICE_TYPE_ROLE
 S ----    1-ff00:0:112      -      -      -     -               -                   -
 0 -E--    1-ff00:0:112      2      0    494     1      ff00:0:112     BR (scionproto)
 1 I---    1-ff00:0:111      2    103    101     1      ff00:0:111     BR (scionproto)
 1 -E--    1-ff00:0:111      1      0    101     1      ff00:0:111     BR (scionproto)
 2 IE--    2-ff00:0:211      1      5      4     2      ff00:0:211     BR (scionproto)
 3 I---    2-ff00:0:222      1    301      0     2      ff00:0:222     BR (scionproto)

Reverse:
  Flags       Source AS NodeID IgPort EgPort   ISD             ASN    DEVICE_TYPE_ROLE
 S ----    2-ff00:0:222      -      -      -     2      ff00:0:222    Host (scion-cpp)
 0 -E--    2-ff00:0:222      1      0    301     2      ff00:0:222     BR (scionproto)
 1 IE--    2-ff00:0:211      1      4      5     2      ff00:0:211     BR (scionproto)
 2 I---    1-ff00:0:111      1    101    103     1      ff00:0:111     BR (scionproto)
 2 -E--    1-ff00:0:111      2      0    103     1      ff00:0:111     BR (scionproto)
 3 I---    1-ff00:0:112      2    494      0     1      ff00:0:112     BR (scionproto)
"""

EXPECTED_AGGREGATION = """\
Source: 1-ff00:0:112,127.0.0.1:32000 Dest: [2-ff00:0:222,fd00:f00d:cafe::7f00:53]:32001
Path: 1-ff00:0:112 494>103 1-ff00:0:111 105>112 1-ff00:0:130 105>1 1-ff00:0:120 6>1 1-ff00:0:110 3>453 2-ff00:0:210 451>7 2-ff00:0:211 4>301 2-ff00:0:222

Forward:
  Flags       Source AS NodeID  Count             ASN
 S ----    1-ff00:0:112      -      -               -
 0 -E--    1-ff00:0:112      2      1      ff00:0:112
 1 IE--    1-ff00:0:111      2      1      ff00:0:111
 2 IE--    1-ff00:0:130      2      1      ff00:0:130
 4 IE--    1-ff00:0:120      1      1      ff00:0:120
 5 IEA-    1-ff00:0:110      3      2      ff00:0:110
 6 IEA-    2-ff00:0:210      3      2      ff00:0:210
 8 IE--    2-ff00:0:211      1      1      ff00:0:211
 9 I---    2-ff00:0:222      1      1      ff00:0:222

Reverse:
  Flags       Source AS NodeID  Count             ASN
 S ----    2-ff00:0:222      -      -      ff00:0:222
 0 -E--    2-ff00:0:222      1      1      ff00:0:222
 1 IE--    2-ff00:0:211      1      1      ff00:0:211
 2 IEA-    2-ff00:0:210      1      2      ff00:0:210
 4 IEA-    1-ff00:0:110      1      2      ff00:0:110
 5 IE--    1-ff00:0:120      1      1      ff00:0:120
 6 IE--    1-ff00:0:130      2      1      ff00:0:130
 8 IE--    1-ff00:0:111      2      1      ff00:0:111
 9 I---    1-ff00:0:112      2      1      ff00:0:112
"""

class IdIntTraceroute(unittest.TestCase):
    def __init__(self, methodName, build_dir):
        super().__init__(methodName)
        self.command = Path(build_dir) / "examples/Debug/idint-traceroute"

    def setUp(self):
        self.server = subprocess.Popen([
            self.command, "server",
            "--sciond", "[fd00:f00d:cafe::7f00:54]:30255",
            "--local", "[fd00:f00d:cafe::7f00:53]:32001"
        ], stdout=DEVNULL)
        time.sleep(0.2)
        self.maxDiff=None

    def tearDown(self):
        self.server.terminate()
        self.server.wait()

    def test_peering_path(self):
        """Path contains a peering shortcut"""
        self.assertIsNone(self.server.poll())
        for i in range(2): # ignore first probe so BR can fetch keys
            res = subprocess.run([
                self.command, "client",
                "[2-ff00:0:222,fd00:f00d:cafe::7f00:53]:32001",
                "--sciond", "127.0.0.60:30255",
                "--local", "127.0.0.1:32000",
                "--nid", "--igr", "--egr",
                "-1", "ISD",
                "-2", "ASN",
                "-3", "DEVICE_TYPE_ROLE",
                "-p", "0"
            ], stdout=PIPE, check=True)
            if i == 0:
                time.sleep(0.5)
        self.assertEqual(res.stdout.decode(), EXPECTED_PEERING_PATH)

    def test_encrypted(self):
        """Encrypted telemetry"""
        self.assertIsNone(self.server.poll())
        for i in range(2): # ignore first probe so BR can fetch keys
            res = subprocess.run([
                self.command, "client",
                "[2-ff00:0:222,fd00:f00d:cafe::7f00:53]:32001",
                "--sciond", "127.0.0.60:30255",
                "--local", "127.0.0.1:32000",
                "-1", "HOST_CPU_NOW",
                "-2", "RTT_NEXT_BR",
                "-3", "INST_QUEUE_LEN",
                "-4", "INGRESS_TSTAMP",
                "--encrypt",
                "-p", "40"
            ], stdout=PIPE, check=True)
            if i == 0:
                time.sleep(0.5)
        self.assertEqual(res.stdout.decode().splitlines()[4],
            "  Flags       Source AS  HOST_CPU_NOW RTT_NEXT_BR  INST_QUEUE_LEN INGRESS_TSTAMP")

    def test_aggregation(self):
        """Per-AS telemetry aggregation"""
        self.assertIsNone(self.server.poll())
        for i in range(2): # ignore first probe so BR can fetch keys
            res = subprocess.run([
                self.command, "client",
                "[2-ff00:0:222,fd00:f00d:cafe::7f00:53]:32001",
                "--sciond", "127.0.0.60:30255",
                "--local", "127.0.0.1:32000",
                "--nid", "--nc", "-a", "AS",
                "-1", "ASN",
                "--af1", "first",
                "--af2", "last",
                "--af3", "min",
                "--af4", "max",
                "-p", "40"
            ], stdout=PIPE, check=True)
            if i == 0:
                time.sleep(0.5)
        self.assertEqual(res.stdout.decode(), EXPECTED_AGGREGATION)
