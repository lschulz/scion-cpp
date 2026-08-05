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
import json
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
    subprocess.run([str(Path(__file__).with_name("run_scion.sh"))],
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
    subprocess.run([str(Path(__file__).with_name("stop_scion.sh"))],
        env={"SCION_ROOT": args.scion, **os.environ}, check=True)
    print("Remove links and namespaces")
    subprocess.run(["sudo", str(Path(__file__).with_name("teardown.sh"))], check=True)


class ScitraMultipathBase:
    """Base class that runs Scitra-TUN with support for MPTCP"""
    def __init__(self, methodName, build_dir):
        super().__init__(methodName)
        self.scitra_tun = Path(build_dir) / "scitra/Debug/scitra-tun-d"

    def setUp(self):
        self.scitra_inst0 = subprocess.Popen([
            "sudo", "ip", "netns", "exec", "host0",
            self.scitra_tun, "veth0", "10.128.0.2", "--extra", "fd00::1", "fd00::2",
            "-d", "10.128.0.1:30255", "--scmp", "-l", "debug"
        ], stdout=PIPE, stderr=STDOUT)
        self.scitra_inst1 = subprocess.Popen([
            "sudo", "ip", "netns", "exec", "host1",
            self.scitra_tun, "veth8", "10.128.4.2", "--extra", "fd00::1", "fd00::2",
            "-d", "10.128.4.1:30255", "--ports", "32000", "--scmp", "-l", "debug"
        ], stdout=PIPE, stderr=STDOUT)
        time.sleep(5)
        # Prime path cache
        subprocess.run([
            "sudo", "ip", "netns", "exec", "host0",
            "ping", "fc00:10fc:200::ffff:a80:402", "-W", "0.2", "-i", "0.1", "-c", "2"
        ], stdout=DEVNULL, stderr=DEVNULL)

    def tearDown(self):
        self.scitra_inst0.terminate()
        self.scitra_inst1.terminate()
        self.scitra_inst0.communicate()
        self.scitra_inst1.communicate()

    def flush_mptcp_endpoints(self, namespace):
        subprocess.run([
            "sudo", "ip", "netns", "exec", namespace,
            "ip", "mptcp", "endpoint", "flush"
        ], stdout=DEVNULL, stderr=DEVNULL, check=True)

    def add_mptcp_endpoint(self, namespace, addr, dev, flag):
        subprocess.run([
            "sudo", "ip", "netns", "exec", namespace,
            "ip", "mptcp", "endpoint", "add", addr, "dev", dev, flag
        ], stdout=DEVNULL, stderr=DEVNULL, check=True)

    def set_mptcp_limits(self, namespace, add_addr_accepted, subflows):
        subprocess.run([
            "sudo", "ip", "netns", "exec", namespace,
            "ip", "mptcp", "limits", "set",
            "add_addr_accepted", str(add_addr_accepted), "subflows", str(subflows)
        ], stdout=DEVNULL, stderr=DEVNULL, check=True)


class MPNetcat(ScitraMultipathBase, unittest.TestCase):
    """Test MPTCP connection with three subflows"""
    def __init__(self, methodName, build_dir="build"):
        super().__init__(methodName, build_dir)
        self.command = ["mptcpize", "run", "nc"]

    def setUp(self):
        super().setUp()
        self.set_mptcp_limits("host0", 4, 6)
        self.set_mptcp_limits("host1", 4, 6)
        self.flush_mptcp_endpoints("host0")
        self.add_mptcp_endpoint("host0", "fc00:10fc:100::ffff:a80:2", "scion", "subflow")
        self.add_mptcp_endpoint("host0", "fd00::1", "scion", "subflow")
        self.add_mptcp_endpoint("host0", "fd00::2", "scion", "subflow")
        self.flush_mptcp_endpoints("host1")
        time.sleep(1)
        self.server = subprocess.Popen([
            "sudo", "ip", "netns", "exec", "host1",
            *self.command, "-6", "-l", "32000"
        ], stdin=PIPE, stdout=PIPE, stderr=DEVNULL)
        os.set_blocking(self.server.stdout.fileno(), False)

    def tearDown(self):
        self.server.stdout.close()
        self.server.terminate()
        self.server.wait()
        super().tearDown()

    def test_multipath_netcat(self):
        self.assertIsNone(self.server.poll())
        client = subprocess.Popen([
            "sudo", "ip", "netns", "exec", "host0",
            *self.command, "fc00:10fc:200::ffff:a80:402", "32000"
        ], stdin=PIPE, stdout=PIPE, stderr=DEVNULL)
        os.set_blocking(client.stdout.fileno(), False)
        client.stdin.write("client->server\n".encode())
        client.stdin.flush()
        client.stdin.close()
        self.server.stdin.write("server->client\n".encode())
        self.server.stdin.flush()
        self.server.stdin.close()
        time.sleep(1)

        flows = subprocess.run(["sudo", "ip", "netns", "exec", "host0", "ss", "-Mani"
        ], stdout=PIPE, check=True)
        self.assertGreater(flows.stdout.decode().find("subflows:2"), 0)

        self.assertEqual(self.server.stdout.readline().decode(), "client->server\n")
        self.assertEqual(client.stdout.readline().decode(), "server->client\n")
        client.stdout.close()
        client.wait()


class ScionBWAggregation(ScitraMultipathBase, unittest.TestCase):
    """Test bandwidth aggregation of three SCION paths using iperf3"""
    def __init__(self, methodName, build_dir="build"):
        super().__init__(methodName, build_dir)
        self.command = ["mptcpize", "run", "iperf3"]

    def setUp(self):
        super().setUp()
        self.set_mptcp_limits("host0", 4, 6)
        self.set_mptcp_limits("host1", 4, 6)
        self.flush_mptcp_endpoints("host0")
        self.add_mptcp_endpoint("host0", "fc00:10fc:100::ffff:a80:2", "scion", "subflow")
        self.add_mptcp_endpoint("host0", "fd00::1", "scion", "subflow")
        self.add_mptcp_endpoint("host0", "fd00::2", "scion", "subflow")
        self.flush_mptcp_endpoints("host1")
        time.sleep(1)
        self.server = subprocess.Popen([
            "sudo", "ip", "netns", "exec", "host1",
            *self.command, "-s", "-p", "32000"
        ], stdout=DEVNULL, stderr=DEVNULL)
        time.sleep(1)

    def tearDown(self):
        self.server.terminate()
        self.server.wait()
        super().tearDown()

    def test_bandwidth_aggregation(self):
        self.assertIsNone(self.server.poll())
        client = subprocess.run([
            "sudo", "ip", "netns", "exec", "host0",
            *self.command, "-c", "fc00:10fc:200::ffff:a80:402",
            "-p", "32000", "-O", "5", "-t", "10", "-b", "30M", "-J"
        ], stdout=PIPE, check=True, timeout=30)
        res = json.loads(client.stdout.decode())
        # Combined send rate should be 30 Mbit/s
        send_rate = float(res["end"]["sum_sent"]["bits_per_second"])
        self.assertGreater(send_rate, 25e6)


class HybridBWAggregation(ScitraMultipathBase, unittest.TestCase):
    """Test bandwidth aggregation between SCION and IP using iperf3"""
    def __init__(self, methodName, build_dir="build"):
        super().__init__(methodName, build_dir)
        self.command = ["mptcpize", "run", "iperf3"]

    def setUp(self):
        super().setUp()
        self.set_mptcp_limits("host0", 4, 6)
        self.set_mptcp_limits("host1", 4, 6)
        self.flush_mptcp_endpoints("host0")
        self.add_mptcp_endpoint("host0", "fc00:10fc:100::ffff:a80:2", "scion", "subflow")
        self.add_mptcp_endpoint("host0", "fd03::1", "vethA", "subflow")
        self.flush_mptcp_endpoints("host1")
        self.add_mptcp_endpoint("host1", "fc00:10fc:200::ffff:a80:402", "scion", "signal")
        self.add_mptcp_endpoint("host1", "fd03::2", "vethB", "signal")
        time.sleep(1)
        self.server = subprocess.Popen([
            "sudo", "ip", "netns", "exec", "host1",
            *self.command, "-s", "-p", "32000"
        ], stdout=DEVNULL, stderr=DEVNULL)
        time.sleep(1)

    def tearDown(self):
        self.server.terminate()
        self.server.wait()
        super().tearDown()

    def test_hybrid_bandwidth(self):
        self.assertIsNone(self.server.poll())
        client = subprocess.run([
            "sudo", "ip", "netns", "exec", "host0",
            *self.command, "-c", "fc00:10fc:200::ffff:a80:402",
            "-p", "32000", "-O", "5", "-t", "10", "-b", "20M", "-J"
        ], stdout=PIPE, check=True, timeout=30)
        res = json.loads(client.stdout.decode())
        # Combined send rate of one SCION flow and direct link should be 20 Mbit/s
        send_rate = float(res["end"]["sum_sent"]["bits_per_second"])
        self.assertGreater(send_rate, 18e6)


def suite(build_dir):
    suite = unittest.TestSuite()
    suite.addTest(MPNetcat("test_multipath_netcat", build_dir))
    suite.addTest(ScionBWAggregation("test_bandwidth_aggregation", build_dir))
    suite.addTest(HybridBWAggregation("test_hybrid_bandwidth", build_dir))
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
