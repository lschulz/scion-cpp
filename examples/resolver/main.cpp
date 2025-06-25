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

#include <scion/daemon/client.hpp>
#include <scion/resolver.hpp>

#include <CLI/CLI.hpp>
#include <boost/asio.hpp>

#include <cstdlib>
#include <iostream>

using namespace scion;
using std::uint16_t;


struct Arguments
{
    std::string name;
    std::string sciond = "127.0.0.1:30255";
    std::string hostsFile = scion::HOSTS_FILE;
};

Maybe<ScIPAddress> getLocalhost(const char* sciond)
{
    daemon::GrpcDaemonClient daemon(sciond);
    auto localAS = daemon.rpcAsInfo(IsdAsn());
    if (isError(localAS)) return propagateError(localAS);
    auto localhost = generic::IPAddress::MakeIPv6(0, 1);
    if (auto addr = generic::IPEndpoint::Parse(sciond); addr.has_value()) {
        if (addr->getHost().is4()) {
            localhost = generic::IPAddress::MakeIPv4(0x7f000001);
        }
    }
    return ScIPAddress(localAS->isdAsn, localhost);
}

int main(int argc, char* argv[])
{
    Arguments args;
    CLI::App app{"Resolves a host name to SCION addresses"};
    app.add_option("name", args.name, "Name to look up")->required();
    app.add_option("-d,--sciond", args.sciond, "SCION daemon address")
        ->capture_default_str()->envname("SCION_DAEMON_ADDRESS");
    app.add_option("--hosts", args.hostsFile, "Override path to hosts file")
        ->capture_default_str();
    CLI11_PARSE(app, argc, argv);

    Resolver resolver;
    if (auto ec = resolver.initialize(); ec) {
        std::cerr << "Error initializing resolver: " << fmtError(ec) << '\n';
        return EXIT_FAILURE;
    }
    if (auto localhost = getLocalhost(args.sciond.c_str()); localhost.has_value()) {
        resolver.setLocalhost(Resolver::AddressSet{*localhost});
    }
    resolver.setHostsFile(args.hostsFile);

    boost::asio::io_context ioCtx;
    auto resolve = [&] () -> boost::asio::awaitable<std::error_code> {
        auto split = resolver.splitHostPort(args.name);
        if (isError(split)) co_return split.error();
        auto [host, port] = *split;
        auto addresses = co_await resolver.resolveHostAsync(
            std::string(host), ioCtx, boost::asio::use_awaitable);
        if (isError(addresses)) co_return addresses.error();
        for (auto&& addr : *addresses) {
            if (port)
                std::cout << ScIPEndpoint(addr, port) << '\n';
            else
                std::cout << addr << '\n';
        }
        co_return ErrorCode::Ok;
    };

    auto result = boost::asio::co_spawn(ioCtx, resolve, boost::asio::use_future);
    ioCtx.run();
    if (auto ec = result.get(); ec) {
        std::cerr << "Error: " << fmtError(ec) << '\n';
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
