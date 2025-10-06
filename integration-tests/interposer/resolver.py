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
from subprocess import DEVNULL, PIPE


class InterposedResolver(unittest.TestCase):
    def __init__(self, methodName, build_dir="build"):
        super().__init__(methodName)
        self.command = Path(build_dir) / "interposer/integration/Debug/" / "interposer-resolver"
        self.env = {
            "LD_PRELOAD": Path(build_dir) / "interposer/Debug/libinterposer.so",
            "SCION_CONFIG": Path(__file__).parent / "config/scion_interposer.toml",
        }

    def test_resolver(self):
        res = subprocess.run([
            self.command, "netsys.ovgu.de"
        ], env={
            "SCION_DAEMON_ADDRESS": "127.0.0.19:30255",
            **self.env
        }, stdout=PIPE, stderr=DEVNULL)
        self.assertEqual(res.stdout.decode(),
            "[19-ffaa:1:c3f,127.0.0.1]:0\n"
            "[141.44.17.123]:0\n")
