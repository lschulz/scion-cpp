// Copyright (c) 2024-2025 Lars-Christian Schulz
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#include "scitra/linux/cli_args.hpp"
#include "scitra/linux/scitra_tun.hpp"
#include "scitra/linux/sys_net.hpp"

#include <iostream>
#include <system_error>


Arguments parseCommandLine(int argc, char* argv[])
{
    Arguments args;
    CLI::App app{"Scitra: SCION-IP Translator for Linux"};
    app.add_option("public_interface", args.publicInterface,
        "Main network interface through which other SCION hosts can be reached")
        ->required();;
    app.add_option("public_address", args.publicAddress,
        "IP address for SCION. Must either be an IPv4 or SCION-mapped IPv6 address.")
        ->required();
    app.add_option("-d,--sciond", args.sciond,
        "SCION daemon address (default \"127.0.0.1:30255\")")
        ->envname("SCION_DAEMON_ADDRESS");
    app.add_option("-n,--tun-name", args.tunDevice,
        "Name of the TUN device created by Scitra (default \"scion\")");
    app.add_flag("-p,--ports", args.ports,
        "Comma-separated list of statically forwarded TCP/UDP ports.");
    app.add_option("-q,--queues", args.queues,
        "Number of TUN queues to create (default 1, max. 64)")
        ->check(CLI::Range(1, 64));
    app.add_option("-t,--threads", args.threads,
        "Number of worker threads to create (default 1, max. 64)")
        ->check(CLI::Range(1, 64));
    app.add_option("--mtu", args.mtu,
        "MTU of the TUN interface. Determined automatically if not given.")
        ->check(CLI::Range(1280, 9000));
    app.add_flag("--policy", args.policy,
        "Path to a JSON file containing path policies");
    app.add_flag("--dispatch", args.enabledDispatch,
        "Assume the duties of the dispatcher and listen on UDP port 30041");
    app.add_flag("--no-tui", args.noTui, "Don't render the UI");
    app.add_flag("--no-device-bind", args.noDeviceBind,
        "Don't bind SCION sockets to public interface. Useful when all SCION"
        " services run on loopback.");
    try {
        app.parse(argc, argv);
        return args;
    }
    catch (const CLI::ParseError& e) {
        std::exit(app.exit(e));
    }
}

void blockSignals()
{
    sigset_t sigset;
    sigfillset(&sigset);
    if (pthread_sigmask(SIG_BLOCK, &sigset, nullptr))
        throw std::system_error(errno, std::generic_category());
}

int main(int argc, char* argv[])
{
    Arguments args = parseCommandLine(argc, argv);
    try {
        blockSignals();
        ScitraTun app(args);
        app.run(args);
        app.join();
    }
    catch (const std::exception& e) {
        std::cerr << e.what() << std::endl;
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
