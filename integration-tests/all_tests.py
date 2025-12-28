#!/bin/env python
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

import argparse
import subprocess
import time
import unittest
from pathlib import Path

from examples import test_suite as examples_test_suite
from examples.c_interface import test_suite as c_examples_test_suite
from interposer import test_suite as interposer_test_suite


def parse_arguments():
    parser = argparse.ArgumentParser(description="Runs all integration tests")
    parser.add_argument("-s", "--scion", type=Path, default=Path.home() / "scionproto-scion",
        help="Absolute path to local copy of scionproto/scion from which to run the test topology")
    parser.add_argument("-b", "--build", type=Path, default="build",
        help="Path to CMake build directory")
    parser.add_argument("--use-existing", action='store_true',
        help="Dont't try to start and stop a new local SCION topology.")
    return parser.parse_args()


def setUpModule(args):
    """
    Starts a local SCION topology from a user provided copy of the
    scionproto/scion repository. All tests use the tiny4 topology.
    """
    if args.use_existing:
        return
    print("Starting local topology")
    subprocess.run([
        args.scion / "scion.sh",
        "topology", "-c", "topology/tiny4.topo"
    ], cwd=args.scion, check=True)
    subprocess.run([
        args.scion / "scion.sh",
        "run",
    ], cwd=args.scion, check=True)
    print("Wait for beacons")
    time.sleep(5)


def tearDownModule(args):
    """
    Stop the local SCION topology.
    """
    if args.use_existing:
        return
    print("Stopping local topology")
    subprocess.run([
        args.scion / "scion.sh",
        "stop",
    ], cwd=args.scion, check=True)


def suite(build_dir):
    suite = unittest.TestSuite()
    suite.addTest(examples_test_suite(build_dir))
    suite.addTest(c_examples_test_suite(build_dir))
    suite.addTest(interposer_test_suite(build_dir))
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
    setUpModule(args)
    try:
        ret = not runner.run(suite(args.build)).wasSuccessful()
    finally:
        tearDownModule(args)
    exit(ret)
