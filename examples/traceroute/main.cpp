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
#include <boost/asio.hpp>
#include <scion/scion_asio.hpp>

#include <cstdlib>
#include <format>
#include <iostream>
#include <memory>
#include <random>
#include <vector>

using std::uint16_t;
using std::size_t;


struct Arguments
{
    std::string sciond = "127.0.0.1:30255";
    std::string localAddr;
    std::string remoteAddr;
    bool interactive = false;
};

int main(int argc, char* argv[])
{
    Arguments args;
    CLI::App app{"UDP/SCION echo client and server"};
    app.add_option("destination", args.remoteAddr, "Destination host")->required();
    app.add_option("-d,--sciond", args.sciond,
        "SCION daemon address (default \"127.0.0.1:30255\")")
        ->envname("SCION_DAEMON_ADDRESS");
    app.add_option("-l,--local", args.localAddr, "Local IP address and port");
    app.add_flag("-i,--interactive", args.interactive, "Prompt for path selection");
    CLI11_PARSE(app, argc, argv);

    using namespace scion;
    using namespace scion::asio;
    using namespace std::chrono_literals;
    using Socket = scion::asio::ScmpSocket;
    using boost::asio::awaitable;

    // Get local AS info from daemon
    daemon::GrpcDaemonClient sciond(args.sciond);
    auto localAS = sciond.rpcAsInfo(IsdAsn());
    if (isError(localAS)) {
        std::cerr << "Error connecting to sciond at " << args.sciond << " : "
            << fmtError(localAS.error()) << '\n';
        return EXIT_FAILURE;
    }
    auto ports = sciond.rpcPortRange();
    if (isError(ports)) {
        ports = std::make_pair<uint16_t, uint16_t>(0, 65535);
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

    // Parse destination address
    auto remote = Socket::Address::Parse(args.remoteAddr).and_then(
        [] (auto&& addr) -> Maybe<Socket::Endpoint> { return Socket::Endpoint(addr, 0);});
    if (isError(remote)) {
        std::cerr << "Invalid destination address: " << args.remoteAddr << '\n';
        return EXIT_FAILURE;
    }

    // Create and bind socket
    boost::asio::io_context ioCtx(1);
    Socket s(ioCtx);
    if (auto ec = s.bind(bindAddress, ports->first, ports->second); ec) {
        std::cerr << "Can't bind to " << bindAddress << " : " << fmtError(ec) << '\n';
        return EXIT_FAILURE;
    }
    std::cout << "Bound to " << s.localEp() << '\n';

    // Get path to destination
    std::vector<PathPtr> paths;
    auto flags = daemon::PathReqFlags::Refresh | daemon::PathReqFlags::AllMetadata;
    auto ec = sciond.rpcPaths(bindAddress.isdAsn(), remote->isdAsn(), flags,
        std::back_inserter(paths));
    if (ec || paths.empty()) {
        std::cerr << "No path to " << remote->isdAsn() << '\n';
        return EXIT_FAILURE;
    }
    PathPtr path;
    if (args.interactive) {
        path = paths[promptForPath(paths)];
    } else {
        std::random_device rng;
        std::uniform_int_distribution<> dist(0, (int)(paths.size() - 1));
        path = paths[dist(rng)];
    }
    auto nextHop = toUnderlay<Socket::UnderlayEp>(path->nextHop()).value();

    // Decode data plane path, so we can set the router alert flags
    DecodedScionPath decoded(path->firstAS(), path->lastAS());
    if (path->type() != hdr::PathType::SCION) {
        std::cerr << "Path not supported\n";
        return EXIT_FAILURE;
    } else {
        ReadStream rs(path->encoded());
        decoded.serialize(rs, NullStreamError);
    }
    std::cout << "Using path: " << *path << '\n';

    using clock = std::chrono::high_resolution_clock;
    std::vector<clock::time_point> probeTimestamps;
    std::size_t probeCount = 2 * decoded.hopFields().size();
    probeTimestamps.reserve(probeCount);

    // Send loop
    HeaderCache headers;
    auto rawPath = std::make_unique<RawPath>();
    auto send = [&] (Socket& s) -> awaitable<void>
    {
        constexpr auto token = boost::asio::use_awaitable;
        boost::asio::high_resolution_timer timer(ioCtx);
        hdr::ScmpTraceRequest request = {
            .id = s.localEp().port(), // routers use id as the port to respond to
            .seq = 0,
        };

        // For simplicity, we blindly send two probes per hop field, one for the ingress router and
        // one for egress. Since not all hop fields and ingress/egress positions actually correspond
        // to routers, we are sending more probes than strictly necessary.
        bool firstHop = true;
        for (auto& hf : decoded.hopFields()) {
            hf.flags = hdr::HopField::Flags::CEgrRouterAlert;
            for (int i = 0; i < 2; ++i) {
                if (!firstHop) {
                    // wait in between probes
                    timer.expires_after(25ms);
                    co_await timer.async_wait(token);
                }
                firstHop = false;
                probeTimestamps.push_back(clock::now());
                rawPath->encode(decoded, NullStreamError);
                auto sent = co_await s.sendScmpToAsync(headers, *remote, *rawPath, nextHop, request,
                    std::views::empty<std::byte>, token);
                if (isError(sent)) co_return;
                request.seq++;
                hf.flags = hdr::HopField::Flags::CIngRouterAlert;
            }
            hf.flags = NoFlags;
        }
    };

    // Receive loop
    auto receive = [&] (Socket& s) -> awaitable<void>
    {
        using namespace std::chrono;
        constexpr auto token = boost::asio::use_awaitable;

        Socket::Endpoint from;
        Socket::UnderlayEp ulSource;
        std::unique_ptr<RawPath> rp;
        std::vector<std::byte> buffer(1024);
        hdr::ScmpMessage message;
        std::size_t responses = 0;

        while (responses < probeCount) {
            auto recvd = co_await s.recvScmpFromViaAsync(
                buffer, from, *rp, ulSource, message, token);
            if (recvd.has_value() && std::holds_alternative<hdr::ScmpTraceReply>(message)) {
                ++responses;
                auto reply = std::get<hdr::ScmpTraceReply>(message);
                if (reply.seq >= probeTimestamps.size()) continue;
                if (reply.sender.isUnspecified())
                    continue; // response to one of the superfluous probes

                auto rtt = duration_cast<microseconds>(
                    clock::now() - probeTimestamps[reply.seq]).count();
                std::cout << std::format("{} {} IfID={} {:.3}ms\n",
                    reply.seq, reply.sender, reply.iface, (double)rtt / 1000.0);
            }
        }
    };

    boost::asio::co_spawn(ioCtx, send(s), boost::asio::detached);
    boost::asio::co_spawn(ioCtx, receive(s), boost::asio::detached);
    ioCtx.run_for(1s);

    return EXIT_SUCCESS;
}
