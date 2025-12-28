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

#include "format.hpp"

#include <CLI/CLI.hpp>
#include <scion/scion.hpp>

#include <chrono>
#include <cstdlib>
#include <iostream>
#include <random>
#include <ranges>


struct Arguments
{
    std::string sciond = "127.0.0.1:30255";
    std::string localAddr;
    std::string destination;
    std::size_t initialMtu = -1;
    bool interactive = false;
};

int main(int argc, char* argv[])
{
    using namespace scion;
    using namespace std::chrono_literals;
    using std::size_t;
    using Socket = posix::IpUdpSocket;

    Arguments args;
    CLI::App app{"Find the Path MTU to a UDP echo server"};
    app.add_option("destination", args.destination, "Destination host")->required();
    app.add_option("-d,--sciond", args.sciond,
        "SCION daemon address (default \"127.0.0.1:30255\")")
        ->envname("SCION_DAEMON_ADDRESS");
    app.add_option("-l,--local", args.localAddr, "Local IP address and port");
    app.add_option("-m,--mtu", args.initialMtu, "Initial MTU to try");
    app.add_flag("-i,--interactive", args.interactive, "Prompt for path selection");
    CLI11_PARSE(app, argc, argv);

    auto remote = scion::posix::IpUdpSocket::Endpoint::Parse(args.destination);
    if (isError(remote)) {
        std::cerr << "Invalid destination address: " << args.destination << '\n';
        return EXIT_FAILURE;
    }

    // Get local AS info from daemon
    daemon::GrpcDaemonClient sciond(args.sciond);
    auto localAS = sciond.rpcAsInfo(IsdAsn());
    if (isError(localAS)) {
        std::cerr << "Error connecting to sciond at " << args.sciond << " : "
            << fmtError(localAS.error()) << '\n';
        return EXIT_FAILURE;
    }
    auto portRange = sciond.rpcPortRange();
    if (isError(portRange)) {
        portRange = std::make_pair<uint16_t, uint16_t>(0, 65535);
    }

    // Parse bind address
    auto bindIP = scion::generic::IPEndpoint::UnspecifiedIPv4();
    if (!args.localAddr.empty()) {
        if (auto ip = scion::generic::IPEndpoint::Parse(args.localAddr); ip.has_value()) {
            bindIP = *ip;
        } else {
            std::cerr << "Invalid bind address: " << args.localAddr << '\n';
            return EXIT_FAILURE;
        }
    }
    Socket::Endpoint bindAddress(localAS->isdAsn, bindIP);

    // Get path to destination
    PathCache pool;
    auto queryPaths = [&sciond] (PathCache& cache, IsdAsn src, IsdAsn dst) -> std::error_code {
        using namespace daemon;
        std::vector<PathPtr> paths;
        auto flags = PathReqFlags::Refresh | PathReqFlags::AllMetadata;
        sciond.rpcPaths(src, dst, flags, std::back_inserter(paths));
        cache.store(src, dst, paths);
        return ErrorCode::Ok;
    };

    auto paths = pool.lookup(bindAddress.isdAsn(), remote->isdAsn(), queryPaths);
    if (isError(paths) || paths->empty()) {
        std::cerr << "No path to " << remote->isdAsn() << '\n';
        return EXIT_FAILURE;
    }

    PathPtr path;
    if (args.interactive) {
        path = (*paths)[promptForPath(*paths)];
    } else {
        std::random_device rng;
        std::uniform_int_distribution<> dist(0, (int)(paths->size() - 1));
        path = (*paths)[dist(rng)];
    }
    auto nextHop = toUnderlay<Socket::UnderlayEp>(path->nextHop(remote->localEp())).value();

    // Open socket
    Socket s;
    PathMtuDiscoverer pmtu((std::uint16_t)std::min(localAS->mtu, 65535u));
    s.setNextScmpHandler(&pool)->setNextScmpHandler(&pmtu);
    if (auto ec = s.bind(bindAddress, portRange->first, portRange->second); ec) {
        std::cerr << "Can't bind to " << bindAddress << " : " << fmtError(ec) << '\n';
        return EXIT_FAILURE;
    }
    if (auto ec = s.connect(*remote); ec) {
        std::cerr << "Connect failed " << fmtError(ec) << '\n';
        return EXIT_FAILURE;
    }
    if (auto ec = s.setRecvTimeout(500ms); ec) {
        std::cerr << "Setting receive timeout failed: " << fmtError(ec) << '\n';
        return EXIT_FAILURE;
    }

    HeaderCache headers;
    size_t mtu = args.initialMtu;
    if (mtu == (size_t)-1) mtu = pmtu.getMtu(remote->host(), *path);
    std::vector<std::byte> payload(mtu), recvBuffer(mtu);
    std::ranges::generate(payload, [] () -> std::byte {
        return std::byte{(std::uint8_t)std::rand()};
    });

    while (true) {
        // Send request
        std::cout << "Try PMTU = " << mtu << '\n';
        auto hdrSize = s.measure(*path);
        if (isError(hdrSize)) {
            std::cerr << "Error: " << fmtError(hdrSize.error()) << '\n';
            return EXIT_FAILURE;
        }
        if (*hdrSize > mtu) {
            std::cout << "MTU too low for SCION headers";
            return EXIT_FAILURE;
        }
        auto payloadSize = mtu - *hdrSize;
        auto sent = s.send(headers, *path, nextHop, std::views::take(payload, payloadSize));
        if (isError(sent)) {
            std::cerr << "Error: " << fmtError(sent.error()) << '\n';
            return EXIT_FAILURE;
        }

        // Wait for reply or SCMP error
        auto recvd = s.recv(recvBuffer, SMSG_RECV_SCMP);
        if (isError(recvd)) {
            if (recvd.error() != ErrorCode::ScmpReceived) {
                std::cerr << "Error: " << fmtError(recvd.error()) << '\n';
                return EXIT_FAILURE;
            }
            // Retry
            auto newMtu = pmtu.getMtu(remote->host(), *path);
            if (newMtu < mtu) {
                mtu = newMtu;
                continue;
            } else {
                std::cout << "Giving up\n";
                return EXIT_FAILURE;
            }
        } else {
            std::cout << "Found PMTU = " << mtu << '\n';
            return EXIT_SUCCESS;
        }
    }
}
