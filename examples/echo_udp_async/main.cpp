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
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/experimental/concurrent_channel.hpp>
#include <scion/scion_asio.hpp>

#include <random>
#include <thread>

using std::uint16_t;


struct Arguments
{
    std::string sciond = "127.0.0.1:30255";
    std::string localAddr;
    std::string remoteAddr;
    std::string message;
    int count = 1;
    bool show_path = false;
    bool interactive = false;
    bool quiet = false;
};

int runServer(
    const scion::asio::UdpSocket::Endpoint& bind,
    std::pair<uint16_t, uint16_t> ports,
    Arguments& args);
int runClient(
    scion::daemon::GrpcDaemonClient& sciond,
    const scion::asio::UdpSocket::Endpoint& bind,
    std::pair<uint16_t, uint16_t> ports,
    Arguments& args);

int main(int argc, char* argv[])
{
    Arguments args;
    CLI::App app{"UDP/SCION echo client and server"};
    app.add_option("-d,--sciond", args.sciond,
        "SCION daemon address (default \"127.0.0.1:30255\")")
        ->envname("SCION_DAEMON_ADDRESS");
    app.add_option("-l,--local", args.localAddr, "Local IP address and port (required for servers)")
        ->group("Server/Client");
    app.add_option("-r,--remote", args.remoteAddr, "SCION address of the server")
        ->group("Client");
    app.add_option("-m,--message", args.message, "The message clients will send to the server")
        ->group("Client");
    app.add_option("-c,--count", args.count, "Number of messages to send")
        ->group("Client");
    app.add_flag("-s,--show-path", args.show_path, "Print the paths taken by each packet")
        ->group("Server/Client");
    app.add_flag("-i,--interactive", args.interactive, "Prompt for path selection")
        ->group("Client");
    app.add_flag("-q,--quiet", args.quiet, "Print responses as ASCII string")
        ->group("Client");
    CLI11_PARSE(app, argc, argv);

    if (args.localAddr.empty() && args.remoteAddr.empty()) {
        std::cerr << "At least one of local (for servers) and remote (for clients) is required\n";
        return EXIT_FAILURE;
    }

    using namespace scion;

    // Get local AS info from daemon
    agrpc::GrpcContext grpcIoCtx;
    daemon::CoGrpcDaemonClient sciond(grpcIoCtx, args.sciond);
    daemon::AsInfo localAS;
    daemon::PortRange portRange;
    auto getAsInfo = [&] () -> boost::asio::awaitable<std::error_code> {
        using namespace boost::asio::experimental::awaitable_operators;
        // get AS info and SCION port range concurrently
        auto [asInfo, ports] = co_await (
            sciond.rpcAsInfoAsync(IsdAsn()) && sciond.rpcPortRangeAsync());
        if (isError(asInfo)) co_return asInfo.error();
        if (isError(ports)) co_return ports.error();
        localAS = *asInfo;
        portRange = *ports;
        co_return ErrorCode::Ok;
    };
    auto geTAsInfoResult = boost::asio::co_spawn(grpcIoCtx, getAsInfo(), boost::asio::use_future);
    grpcIoCtx.run();
    if (auto ec = geTAsInfoResult.get(); ec) {
        std::cerr << "Error connecting to sciond at " << args.sciond << " : "
            << fmtError(ec) << '\n';
        return EXIT_FAILURE;
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
    scion::asio::UdpSocket::Endpoint bindAddress(localAS.isdAsn, bindIP);

    try {
        if (args.remoteAddr.empty()) {
            return runServer(bindAddress, portRange, args);
        }
        else {
            return runClient(sciond, bindAddress, portRange, args);
        }
    }
    catch (const std::system_error& e) {
        std::cerr << scion::fmtError(e.code()) << std::endl;
        return EXIT_FAILURE;
    }
    catch (const std::exception& e) {
        std::cerr << e.what() << std::endl;
        return EXIT_FAILURE;
    }
}

int runServer(
    const scion::asio::UdpSocket::Endpoint& bind,
    std::pair<uint16_t, uint16_t> ports,
    Arguments& args)
{
    using namespace scion;
    using namespace scion::asio;
    using Socket = UdpSocket;
    using boost::asio::awaitable;

    boost::asio::io_context ioCtx(1);
    Socket s(ioCtx);
    if (auto ec = s.bind(bind, ports.first, ports.second); ec) {
        std::cerr << "Can't bind to " << bind << " : " << fmtError(ec) << '\n';
        return EXIT_FAILURE;
    }
    std::cout << "Server listening at " << s.localEp() << '\n';

    auto echo = [&args] (Socket& s) -> awaitable<std::error_code>
    {
        Socket::Endpoint from;
        Socket::UnderlayEp ulSource;
        HeaderCache headers;
        std::vector<std::byte> buffer(2048);
        auto path = std::make_unique<RawPath>();
        constexpr auto token = boost::asio::use_awaitable;

        while (true) {
            auto recvd = co_await s.recvFromViaAsync(buffer, from, *path, ulSource, token);
            if (recvd.has_value()) {
                std::cout << "Received " << recvd->size() << " bytes from " << from << ":\n";
                std::cout << printBuffer(*recvd);
                if (!path->reverseInPlace()) {
                    if (args.show_path) std::cout << "Path: " << *path << '\n';
                    auto sent = co_await s.sendToAsync(headers, from, *path, ulSource, *recvd, token);
                    if (isError(sent)) {
                        co_return sent.error();
                    }
                }
            } else {
                co_return recvd.error();
            }
        }
    };

    auto futureResult = boost::asio::co_spawn(ioCtx, echo(s), boost::asio::use_future);
    ioCtx.run();
    if (auto ec = futureResult.get(); ec) {
        std::cerr << "Error: " << fmtError(ec) << '\n';
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}

int runClient(
    scion::daemon::GrpcDaemonClient& sciond,
    const scion::asio::UdpSocket::Endpoint& bind,
    std::pair<uint16_t, uint16_t> ports,
    Arguments& args)
{
    using namespace scion;
    using namespace scion::asio;
    using namespace std::chrono_literals;
    using Socket = UdpSocket;
    using boost::asio::awaitable;

    auto remote = Socket::Endpoint::Parse(args.remoteAddr);
    if (isError(remote)) {
        std::cerr << "Invalid destination address: " << args.remoteAddr << '\n';
        return EXIT_FAILURE;
    }

    boost::asio::io_context ioCtx(1);
    SharedPathCache pool;
    using Event = boost::asio::experimental::concurrent_channel<void(boost::system::error_code)>;
    using CoEvent = boost::asio::use_awaitable_t<>::as_default_on_t<Event>;
    CoEvent event(ioCtx);
    auto queryPaths = [&] (SharedPathCache& cache, IsdAsn src, IsdAsn dst) -> std::error_code {
        // query paths from a different thread and return immediately
        std::thread([&] (SharedPathCache& cache, IsdAsn src, IsdAsn dst) {
            using namespace daemon;
            std::vector<PathPtr> paths;
            auto flags = PathReqFlags::Refresh | PathReqFlags::AllMetadata;
            sciond.rpcPaths(src, dst, flags, std::back_inserter(paths));
            cache.store(src, dst, paths);
            event.try_send(boost::system::error_code{});
        }, std::ref(cache), src, dst).detach();
        return ErrorCode::Pending;
    };

    Socket s(ioCtx);
    s.setNextScmpHandler(&pool);
    if (auto ec = s.bind(bind, ports.first, ports.second); ec) {
        std::cerr << "Can't bind to " << bind << " : " << fmtError(ec) << '\n';
        return EXIT_FAILURE;
    }
    s.connect(*remote);

    boost::asio::steady_timer timer(ioCtx);
    auto run = [&] (Socket& s) -> awaitable<std::error_code>
    {
        constexpr auto token = boost::asio::use_awaitable;

        auto paths = pool.lookup(bind.isdAsn(), remote->isdAsn(), queryPaths);
        if (isError(paths) && paths.error() == ErrorCode::Pending) {
            // wait for first batch of paths
            co_await event.async_receive();
            paths = pool.lookupCached(bind.isdAsn(), remote->isdAsn());
        }
        if (isError(paths) || paths->empty()) {
            std::cerr << "No path to " << remote->isdAsn() << '\n';
            co_return ErrorCode::Cancelled;
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

        // give up after 1 second
        timer.expires_after(1s);
        timer.async_wait([&] (boost::system::error_code) { s.close(); });

        Socket::Endpoint from;
        Socket::UnderlayEp ulSource;
        HeaderCache headers;
        std::vector<std::byte> sendBuffer, recvBuffer;
        if (args.message.empty()) args.message = "Hello!";
        sendBuffer.reserve(args.message.size());
        std::ranges::transform(args.message, std::back_inserter(sendBuffer), [] (char c) {
            return std::byte{(unsigned char)c};
        });
        recvBuffer.resize(2048);
        for (int i = 0; i < args.count; ++i) {
            auto sent = co_await s.sendAsync(headers, *path, nextHop, sendBuffer, token);
            if (isError(sent)) co_return sent.error();

            auto recvd = co_await s.recvFromAsync(recvBuffer, from, ulSource, token);
            if (isError(recvd)) co_return recvd.error();

            if (!args.quiet) {
                std::cout << "Received " << recvd->size() << " bytes from " << from << ":\n";
                std::cout << printBuffer(*recvd);
            } else {
                printEscapedString(std::cout, *recvd);
            }
        }
        timer.cancel();
        co_return ErrorCode::Ok;
    };

    auto futureResult = boost::asio::co_spawn(ioCtx, run(s), boost::asio::use_future);
    ioCtx.run();
    if (auto ec = futureResult.get(); ec) {
        if (ec == ErrorCondition::Cancelled) {
            std::cerr << "No Response\n";
        } else {
            std::cerr << "Error: " << fmtError(ec) << '\n';
        }
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
