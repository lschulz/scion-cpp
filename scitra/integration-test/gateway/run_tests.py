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
        description="Runs gateway mode and prefix translation integration tests")
    parser.add_argument("suite", choices=["ipv4", "ipv6", "ipv6_prefix_xlat"],
        help="Test suite to run")
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
    base_path = Path(__file__).parent / args.suite
    print("Set up network namespaces and links")
    subprocess.run(["sudo", str(base_path / "setup.sh")], check=True)
    print("Starting local topology")
    subprocess.run([str(base_path / "run_scion.sh")],
        env={"SCION_ROOT": args.scion, **os.environ}, check=True)
    print("Wait for beacons")
    time.sleep(5)


def tearDownNetwork(args):
    """
    Stops SCION and removes the virtual network.
    """
    if args.use_existing:
        return
    base_path = Path(__file__).parent / args.suite
    print("Stopping local topology")
    subprocess.run([str(base_path / "stop_scion.sh")],
        env={"SCION_ROOT": args.scion, **os.environ}, check=True)
    print("Remove links and namespaces")
    subprocess.run(["sudo", str(base_path / "teardown.sh")], check=True)


class GatewayTestBase(unittest.TestCase):
    def __init__(self, methodName):
        super().__init__(methodName)

    def test_ping_from_host0(self):
        res = subprocess.run([
            "sudo", "ip", "netns", "exec", "host0", "ping", "fc00:10fc:200::2",
            "-c", "2", "-p", "FFFF", "-e", "65535", "-W", "0.2", "-i", "0.1", "-c", "2"],
            capture_output=True)
        self.assertEqual(res.returncode, 0)

        res = subprocess.run([
            "sudo", "ip", "netns", "exec", "host0", "ping", "fc00:10fc:200::2",
            "-M", "probe", "-s", "1350", "-W", "0.2", "-i", "0.1", "-c", "2"],
            capture_output=True)
        self.assertNotEqual(res.returncode, 0)
        self.assertEqual(res.stdout.decode().splitlines()[1],
            "From fc00::1 icmp_seq=1 Packet too big: mtu=1388")

    def test_ping_from_scitra(self):
        res = subprocess.run([
            "sudo", "ip", "netns", "exec", "scitra", "ping", "fc00:10fc:200::2",
            "-c", "2", "-p", "FFFF", "-e", "65535", "-W", "0.2", "-i", "0.1", "-c", "2"],
            capture_output=True)
        self.assertEqual(res.returncode, 0)

        res = subprocess.run([
            "sudo", "ip", "netns", "exec", "scitra", "ping", "fc00:10fc:200::2",
            "-M", "probe", "-s", "1350", "-W", "0.2", "-i", "0.1", "-c", "2"],
            capture_output=True)
        self.assertNotEqual(res.returncode, 0)
        self.assertEqual(res.stdout.decode().splitlines()[1],
            "From fc00::1 icmp_seq=1 Packet too big: mtu=1388")

    def test_ping_from_host0_ipv4(self):
        res = subprocess.run([
            "sudo", "ip", "netns", "exec", "host0", "ping", "fc00:10fc:200::2",
            "-c", "2", "-p", "FFFF", "-e", "65535", "-W", "0.2", "-i", "0.1", "-c", "2"],
            capture_output=True)
        self.assertEqual(res.returncode, 0)

        res = subprocess.run([
            "sudo", "ip", "netns", "exec", "host0", "ping", "fc00:10fc:200::2",
            "-M", "probe", "-s", "1400", "-W", "0.2", "-i", "0.1", "-c", "2"],
            capture_output=True)
        self.assertNotEqual(res.returncode, 0)
        self.assertEqual(res.stdout.decode().splitlines()[1],
            "From fc00::1 icmp_seq=1 Packet too big: mtu=1400")

    def test_ping_from_scitra_ipv4(self):
        res = subprocess.run([
            "sudo", "ip", "netns", "exec", "scitra", "ping", "fc00:10fc:200::2",
            "-c", "2", "-p", "FFFF", "-e", "65535", "-W", "0.2", "-i", "0.1", "-c", "2"],
            capture_output=True)
        self.assertEqual(res.returncode, 0)

        res = subprocess.run([
            "sudo", "ip", "netns", "exec", "scitra", "ping", "fc00:10fc:200::2",
            "-M", "probe", "-s", "1400", "-W", "0.2", "-i", "0.1", "-c", "2"],
            capture_output=True)
        self.assertNotEqual(res.returncode, 0)
        self.assertEqual(res.stdout.decode().splitlines()[1],
            "From fc00::1 icmp_seq=1 Packet too big: mtu=1400")

    def test_netcat_from_host1(self):
        self.netcat_udp_test(
            "host2", ["-ul", "fd00::1", "32000"],
            "host1", ["-u", "fc00:10fc:200::2", "32000"])

    def test_netcat_from_scitra(self):
        self.netcat_udp_test(
            "host2", ["-ul", "fd00::1", "32000"],
            "scitra", ["-u", "fc00:10fc:200::2", "32000"])

    def netcat_udp_test(self, server_ns, server_args, client_ns, client_args):
        """Test connectivity with netcat"""

        server = subprocess.Popen([
            "sudo", "ip", "netns", "exec", server_ns, "nc", *server_args
        ], stdin=PIPE, stdout=PIPE, stderr=DEVNULL)
        os.set_blocking(server.stdout.fileno(), False)
        time.sleep(0.2)

        client = subprocess.Popen([
            "sudo", "ip", "netns", "exec", client_ns, "nc", *client_args
        ], stdin=PIPE, stdout=PIPE, stderr=DEVNULL)
        os.set_blocking(client.stdout.fileno(), False)

        client.stdin.write("client->server\n".encode())
        client.stdin.flush()
        client.stdin.close()
        server.stdin.write("server->client\n".encode())
        server.stdin.flush()
        server.stdin.close()
        time.sleep(0.2)
        self.assertEqual(server.stdout.readline().decode(), "client->server\n")
        self.assertEqual(client.stdout.readline().decode(), "server->client\n")
        client.stdout.close()
        client.wait()
        server.stdout.close()
        server.terminate()
        server.wait()


#################
# IPv4 Underlay #
#################


class IPv4Gateway(GatewayTestBase):
    """Gateway mode with IPv4 underlay"""
    def __init__(self, methodName, build_dir):
        super().__init__(methodName)
        self.scitra_tun = Path(build_dir) / "scitra/Debug/scitra-tun-d"
        self.echo_udp_async = Path(build_dir) / "examples/Debug/echo-udp-async"

    def setUp(self):
        self.scitra_inst0 = subprocess.Popen([
            "sudo", "ip", "netns", "exec", "scitra",
            self.scitra_tun, "-a", "10.128.0.2/16", "-t", "fd00:10fc:100::ffff:10.128.0.2",
            "-d", "10.128.0.1:30255", "--mode=gateway", "--scmp", "-l", "debug"
        ], stdout=PIPE, stderr=STDOUT)
        self.scitra_inst1 = subprocess.Popen([
            "sudo", "ip", "netns", "exec", "host2",
            self.scitra_tun, "-a", "fc00:10fc:200::2", "-t", "fd00::1",
            "-d", "[fc00:10fc:200::1]:30255", "-p", "32000", "--scmp", "-l", "debug"
        ], stdout=PIPE, stderr=STDOUT)
        time.sleep(0.2)
        # Prime path cache
        subprocess.run([
            "sudo", "ip", "netns", "exec", "scitra",
            "ping", "fc00:10fc:200::2", "-W", "0.2", "-i", "0.1", "-c", "2"
        ], stdout=DEVNULL, stderr=DEVNULL)

    def tearDown(self):
        self.scitra_inst0.terminate()
        self.scitra_inst1.terminate()
        self.scitra_inst0.communicate()
        self.scitra_inst1.communicate()

    def test_intra_as_echo(self):
        """Test intra-AS connectivity"""

        server = subprocess.Popen([
            self.echo_udp_async, "-d", "10.128.0.1:30255", "-l", "10.128.0.1:32001"
        ], stdout=DEVNULL, stderr=DEVNULL)
        time.sleep(0.2)

        client = subprocess.Popen([
            "sudo", "ip", "netns", "exec", "host1",
            "nc", "-u", "fc00:10fc:100::ffff:10.128.0.1", "32001"
        ], stdin=PIPE, stdout=PIPE, stderr=DEVNULL)
        os.set_blocking(client.stdout.fileno(), False)

        client.stdin.write("test\n".encode())
        client.stdin.flush()
        client.stdin.close()
        time.sleep(0.2)
        self.assertEqual(client.stdout.readline().decode(), "test\n")
        client.stdout.close()
        client.wait()
        server.terminate()
        server.wait()


def suite_ipv4(build_dir):
    suite = unittest.TestSuite()
    suite.addTest(IPv4Gateway("test_ping_from_host0_ipv4", build_dir))
    suite.addTest(IPv4Gateway("test_ping_from_scitra_ipv4", build_dir))
    suite.addTest(IPv4Gateway("test_netcat_from_host1", build_dir))
    suite.addTest(IPv4Gateway("test_netcat_from_scitra", build_dir))
    suite.addTest(IPv4Gateway("test_intra_as_echo", build_dir))
    return suite


#################
# IPv6 Underlay #
#################

class IPv6Gateway(GatewayTestBase):
    """Gateway mode with IPv6 underlay"""
    def __init__(self, methodName, build_dir):
        super().__init__(methodName)
        self.scitra_tun = Path(build_dir) / "scitra/Debug/scitra-tun-d"

    def setUp(self):
        self.scitra_inst0 = subprocess.Popen([
            "sudo", "ip", "netns", "exec", "scitra",
            self.scitra_tun, "-a", "fc00:10fc:100::2/40", "-t", "fd00:10fc:100::2",
            "-d", "[fc00:10fc:100::1]:30255", "--mode=gateway", "--scmp", "-l", "debug"
        ], stdout=PIPE, stderr=STDOUT)
        self.scitra_inst1 = subprocess.Popen([
            "sudo", "ip", "netns", "exec", "host2",
            self.scitra_tun, "-a", "fc00:10fc:200::2", "-t", "fd00::1",
            "-d", "[fc00:10fc:200::1]:30255", "-p", "32000", "--scmp", "-l", "debug"
        ], stdout=PIPE, stderr=STDOUT)
        time.sleep(0.2)
        # Prime path cache
        subprocess.run([
            "sudo", "ip", "netns", "exec", "scitra",
            "ping", "fc00:10fc:200::2", "-W", "0.2", "-i", "0.1", "-c", "2"
        ], stdout=DEVNULL, stderr=DEVNULL)

    def tearDown(self):
        self.scitra_inst0.terminate()
        self.scitra_inst1.terminate()
        self.scitra_inst0.communicate()
        self.scitra_inst1.communicate()


def suite_ipv6(build_dir):
    suite = unittest.TestSuite()
    suite.addTest(IPv6Gateway("test_ping_from_host0", build_dir))
    suite.addTest(IPv6Gateway("test_ping_from_scitra", build_dir))
    suite.addTest(IPv6Gateway("test_netcat_from_host1", build_dir))
    suite.addTest(IPv6Gateway("test_netcat_from_scitra", build_dir))
    return suite


#########################################
# IPv6 Underlay with Prefix Translation #
#########################################


class IPv6PrefixXlatGateway(GatewayTestBase):
    """Gateway mode with underlay prefix translation"""
    def __init__(self, methodName, build_dir):
        super().__init__(methodName)
        self.scitra_tun = Path(build_dir) / "scitra/Debug/scitra-tun-d"

    def setUp(self):
        self.scitra_inst0 = subprocess.Popen([
            "sudo", "ip", "netns", "exec", "scitra",
            self.scitra_tun, "-x", "-a", "fd00:deca:100::2/40", "-t", "fd00:10fc:100::2",
            "-d", "[fd00:deca:100::1]:30255", "--mode=gateway", "--scmp", "-l", "debug"
        ], stdout=PIPE, stderr=STDOUT)
        self.scitra_inst1 = subprocess.Popen([
            "sudo", "ip", "netns", "exec", "host2",
            self.scitra_tun, "-a", "fc00:10fc:200::2", "-t", "fd00::1",
            "-d", "[fc00:10fc:200::1]:30255", "--ports=[fc00:10fc:200::2]:32000",
            "--scmp", "-l", "debug"
        ], stdout=PIPE, stderr=STDOUT)
        time.sleep(0.2)
        # Prime path cache
        subprocess.run([
            "sudo", "ip", "netns", "exec", "scitra",
            "ping", "fc00:10fc:200::2", "-W", "0.2", "-i", "0.1", "-c", "2"
        ], stdout=DEVNULL, stderr=DEVNULL)

    def tearDown(self):
        self.scitra_inst0.terminate()
        self.scitra_inst1.terminate()
        self.scitra_inst0.communicate()
        self.scitra_inst1.communicate()


class IPv6PrefixXlatNorm(GatewayTestBase):
    """Normal mode with underlay prefix translation"""
    def __init__(self, methodName, build_dir):
        super().__init__(methodName)
        self.scitra_tun = Path(build_dir) / "scitra/Debug/scitra-tun-d"

    def setUp(self):
        self.scitra_inst0 = subprocess.Popen([
            "sudo", "ip", "netns", "exec", "scitra",
            self.scitra_tun, "-x", "-a", "fd00:deca:100::2/64", "-t", "fd00:10fc:100::2",
            "-d", "[fd00:deca:100::1]:30255", "--scmp", "-l", "debug"
        ], stdout=PIPE, stderr=STDOUT)
        self.scitra_inst1 = subprocess.Popen([
            "sudo", "ip", "netns", "exec", "host2",
            self.scitra_tun, "-a", "fc00:10fc:200::2", "-t", "fd00::1",
            "-d", "[fc00:10fc:200::1]:30255", "--ports=[fc00:10fc:200::2]:32000",
            "--scmp", "-l", "debug"
        ], stdout=PIPE, stderr=STDOUT)
        time.sleep(0.2)
        # Prime path cache
        subprocess.run([
            "sudo", "ip", "netns", "exec", "scitra",
            "ping", "fc00:10fc:200::2", "-W", "0.2", "-i", "0.1", "-c", "2"
        ], stdout=DEVNULL, stderr=DEVNULL)

    def tearDown(self):
        self.scitra_inst0.terminate()
        self.scitra_inst1.terminate()
        self.scitra_inst0.communicate()
        self.scitra_inst1.communicate()


def suite_ipv6_prefix_xlat(build_dir):
    suite = unittest.TestSuite()
    suite.addTest(IPv6PrefixXlatGateway("test_ping_from_host0", build_dir))
    suite.addTest(IPv6PrefixXlatGateway("test_ping_from_scitra", build_dir))
    suite.addTest(IPv6PrefixXlatGateway("test_netcat_from_host1", build_dir))
    suite.addTest(IPv6PrefixXlatGateway("test_netcat_from_scitra", build_dir))
    suite.addTest(IPv6PrefixXlatNorm("test_ping_from_scitra", build_dir))
    suite.addTest(IPv6PrefixXlatNorm("test_netcat_from_scitra", build_dir))
    return suite


if __name__ == "__main__":
    args = parse_arguments()
    if not args.scion.exists():
        print(f"Directory {args.scion} does not exist")
        exit(1)
    if not args.build.exists():
        print("Build directory not found (override with --build)")
        exit(1)

    runner = unittest.TextTestRunner()
    if args.suite == "ipv4":
        suite = suite_ipv4(args.build)
    elif args.suite == "ipv6":
        suite = suite_ipv6(args.build)
    elif args.suite == "ipv6_prefix_xlat":
        suite = suite_ipv6_prefix_xlat(args.build)

    setUpNetwork(args)
    try:
        ret = not runner.run(suite).wasSuccessful()
    finally:
        tearDownNetwork(args)
    exit(ret)
