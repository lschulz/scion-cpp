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

import os
import subprocess
import time
import unittest
from pathlib import Path
from subprocess import DEVNULL, PIPE


class InterposedNetcat(unittest.TestCase):
    def __init__(self, methodName, build_dir="build"):
        super().__init__(methodName)
        self.command = "nc"
        self.env = {
            "LD_PRELOAD": Path(build_dir) / "interposer/Debug/scion-interposerd.so",
            "SCION_CONFIG": Path(__file__).parent / "config/scion_interposer.toml",
        }

    def setUp(self):
        self.server = subprocess.Popen([
            self.command, "-ul", "0-0,127.0.0.1", "32000"
        ], env={
            "SCION_DAEMON_ADDRESS": "127.0.0.19:30255",
            **self.env
        }, stdin=PIPE, stdout=PIPE, stderr=DEVNULL)
        os.set_blocking(self.server.stdout.fileno(), False)
        time.sleep(0.2)

    def tearDown(self):
        self.server.stdout.close()
        self.server.terminate()
        self.server.wait()

    def test_local(self):
        """Client and server are in the same AS"""
        self.assertIsNone(self.server.poll())
        client = subprocess.Popen([
            self.command,
            "-u", "1-ff00:0:111,127.0.0.1", "32000"
        ], env={
            "SCION_DAEMON_ADDRESS": "127.0.0.19:30255",
            **self.env
        }, stdin=PIPE, stdout=PIPE, stderr=DEVNULL)
        os.set_blocking(client.stdout.fileno(), False)
        client.stdin.write("client->server\n".encode())
        client.stdin.flush()
        client.stdin.close()
        self.server.stdin.write("server->client\n".encode())
        self.server.stdin.flush()
        self.server.stdin.close()
        time.sleep(0.2)
        self.assertEqual(self.server.stdout.readline().decode(), "client->server\n")
        self.assertEqual(client.stdout.readline().decode(), "server->client\n")
        client.stdout.close()
        client.wait()

    def test_remote(self):
        """Client in a different AS than server"""
        self.assertIsNone(self.server.poll())
        client = subprocess.Popen([
            self.command,
            "-u", "1-ff00:0:111,127.0.0.1", "32000"
        ], env={
            "SCION_DAEMON_ADDRESS": "127.0.0.27:30255",
            **self.env
        }, stdin=PIPE, stdout=PIPE, stderr=DEVNULL)
        os.set_blocking(client.stdout.fileno(), False)
        client.stdin.write("client->server\n".encode())
        client.stdin.flush()
        client.stdin.close()
        self.server.stdin.write("server->client\n".encode())
        self.server.stdin.flush()
        self.server.stdin.close()
        time.sleep(0.2)
        self.assertEqual(self.server.stdout.readline().decode(), "client->server\n")
        self.assertEqual(client.stdout.readline().decode(), "server->client\n")
        client.stdout.close()
        client.wait()
