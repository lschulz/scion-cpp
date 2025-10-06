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


class Resolver(unittest.TestCase):
    def __init__(self, methodName, build_dir="build"):
        super().__init__(methodName)
        self.command = Path(build_dir) / "examples/Debug/resolver"
        self.hosts_file = Path(__file__).parent / "data/hosts"

    def test_hosts_file(self):
        res = subprocess.run([
            self.command,
            "--hosts", self.hosts_file,
            "example.com"
        ], stdout=PIPE, check=True)
        self.assertEqual(res.stdout.decode(),
            "1-ff00:0:0,127.0.0.1\n"
            "1-ff00:0:0,::1\n")

    def test_online(self):
        res = subprocess.run([
            self.command, "netsys.ovgu.de"
        ], stdout=PIPE, check=True)
        self.assertEqual(res.stdout.decode(), "19-ffaa:1:c3f,127.0.0.1\n")
