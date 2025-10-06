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
import unittest
from pathlib import Path
from subprocess import PIPE


class Traceroute(unittest.TestCase):
    def __init__(self, methodName, build_dir="build"):
        super().__init__(methodName)
        self.command = Path(build_dir) / "examples/Debug/traceroute"

    def test_traceroute(self):
        res = subprocess.run([
            self.command,
            "--sciond", "127.0.0.19:30255",
            "--local", "127.0.0.1",
            "1-ff00:0:112,127.0.0.1"
        ], stdout=PIPE, check=True)
        lines = res.stdout.decode().splitlines()
        self.assertEqual(len(lines), 6)
        self.assertEqual(lines[0], "Bound to 1-ff00:0:111,127.0.0.1:32767")
        self.assertEqual(lines[1], "Using path: 1-ff00:0:111 41>1 1-ff00:0:110 2>1 1-ff00:0:112")
        self.assertRegex(lines[2], r"1 1-ff00:0:111 IfID=41 \d\.\d+ms")
        self.assertRegex(lines[3], r"2 1-ff00:0:110 IfID=1 \d\.\d+ms")
        self.assertRegex(lines[4], r"4 1-ff00:0:110 IfID=2 \d\.\d+ms")
        self.assertRegex(lines[5], r"7 1-ff00:0:112 IfID=1 \d\.\d+ms")
