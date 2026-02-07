#!/bin/env python
# Copyright (c) 2024-2026 Lars-Christian Schulz
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
import os
import subprocess
import time
import unittest
from pathlib import Path
from subprocess import DEVNULL, PIPE, STDOUT


def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Runs Scitra-TUN integration tests with an IPv6 underlay")
    parser.add_argument("-s", "--scion", type=Path, default=Path.home() / "scionproto-scion",
        help="Absolute path to local copy of scionproto/scion from which to run the test network")
    parser.add_argument("-b", "--build", type=Path, default="build",
        help="Path to CMake build directory")
    parser.add_argument("--use-existing", action='store_true',
        help="Use existing test fixture")
    return parser.parse_args()


def setUpNetwork(args):
    """
    Sets up a virtual network and runs local SCION infrastructure in it.
    """
    if args.use_existing:
        return
    print("Set up network namespaces and links")
    subprocess.run(["sudo", str(Path(__file__).with_name("setup.sh"))], check=True)
    print("Starting local topology")
    subprocess.run([str(Path(__file__).with_name("run_tiny6_bgp.sh"))],
        env={"SCION_ROOT": args.scion, **os.environ}, check=True)
    print("Wait for beacons")
    time.sleep(5)


def tearDownNetwork(args):
    """
    Stops SCION and removes the virtual network.
    """
    if args.use_existing:
        return
    print("Stopping local topology")
    subprocess.run([str(Path(__file__).with_name("stop.sh"))],
        env={"SCION_ROOT": args.scion, **os.environ}, check=True)
    print("Remove links and namespaces")
    subprocess.run(["sudo", str(Path(__file__).with_name("teardown.sh"))], check=True)


class ScitraBase:
    """Base for tests that require Scitra-TUN to be running"""
    def __init__(self, methodName, build_dir):
        super().__init__(methodName)
        self.scitra_tun = Path(build_dir) / "scitra/Debug/scitra-tun-d"

    def setUp(self):
        self.scitra_inst0 = subprocess.Popen([
            "sudo", "ip", "netns", "exec", "host0",
            self.scitra_tun, "veth1", "fc00:10fc:100::2", "-a", "fd00::1",
            "-d", "[fc00:10fc:100::1]:30255", "--scmp", "-l", "debug"
        ], stdout=PIPE, stderr=STDOUT)
        self.scitra_inst1 = subprocess.Popen([
            "sudo", "ip", "netns", "exec", "host1",
            self.scitra_tun, "veth3", "fc00:10fc:200::2", "-a", "fd00::2",
            "-d", "[fc00:10fc:200::1]:30255", "--scmp", "-p", "32000", "-l", "debug"
        ], stdout=PIPE, stderr=STDOUT)
        time.sleep(0.2)
        # Prime path cache
        subprocess.run([
            "sudo", "ip", "netns", "exec", "host0",
            "ping", "fc00:10fc:200::2", "-W", "0.2", "-i", "0.1", "-c", "2"
        ], stdout=DEVNULL, stderr=DEVNULL)

    def tearDown(self):
        self.scitra_inst0.terminate()
        self.scitra_inst1.terminate()
        self.scitra_inst0.wait()
        self.scitra_inst1.wait()


class Netcat(ScitraBase, unittest.TestCase):
    """Test TCP connection"""
    def __init__(self, methodName, build_dir="build"):
        super().__init__(methodName, build_dir)
        self.command = "nc"

    def setUp(self):
        super().setUp()
        self.server = subprocess.Popen([
            "sudo", "ip", "netns", "exec", "host1",
            self.command, "-6", "-l", "fd00::2", "32000"
        ], stdin=PIPE, stdout=PIPE, stderr=DEVNULL)
        os.set_blocking(self.server.stdout.fileno(), False)
        time.sleep(0.2)

    def tearDown(self):
        self.server.stdout.close()
        self.server.terminate()
        self.server.wait()
        super().tearDown()

    def test_netcat(self):
        self.assertIsNone(self.server.poll())
        client = subprocess.Popen([
            "sudo", "ip", "netns", "exec", "host0",
            self.command, "fc00:10fc:200::2", "32000"
        ], stdin=PIPE, stdout=PIPE, stderr=DEVNULL)
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


def suite(build_dir):
    suite = unittest.TestSuite()
    suite.addTest(Netcat("test_netcat", build_dir))
    return suite


if __name__ == "__main__":
    args = parse_arguments()
    if not args.scion.exists():
        print(f"Directory {args.scion} does not exist")
        exit(1)
    if not args.build.exists():
        print("Build directory not found (override with --build)")
        exit(1)
    global scion_dir
    runner = unittest.TextTestRunner()
    setUpNetwork(args)
    try:
        ret = not runner.run(suite(args.build)).wasSuccessful()
    finally:
        tearDownNetwork(args)
    exit(ret)
