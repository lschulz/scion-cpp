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

#include "console.hpp"
#include "format.hpp"

#include <CLI/CLI.hpp>
#include <scion/scion.hpp>

#include <cstdlib>
#include <iostream>
#include <memory>
#include <random>
#include <string>
#include <vector>

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
    bool stun = false;
    bool quiet = false;
};

int runServer(
    const scion::posix::IpUdpSocket::Endpoint& bind,
    std::pair<uint16_t, uint16_t> ports,
    Arguments& args);
int runClient(
    scion::daemon::GrpcDaemonClient& sciond,
    const scion::posix::IpUdpSocket::Endpoint& bind,
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
    app.add_flag("--stun", args.stun,
        "Attempt NAT traversal (requires a STUN server on the path's first hop)")
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
    posix::IpUdpSocket::Endpoint bindAddress(localAS->isdAsn, bindIP);

    try {
        if (args.remoteAddr.empty()) {
            return runServer(bindAddress, *portRange, args);
        }
        else {
            return runClient(sciond, bindAddress, *portRange, args);
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
    const scion::posix::IpUdpSocket::Endpoint& bind,
    std::pair<uint16_t, uint16_t> ports,
    Arguments& args)
{
    using namespace std::chrono_literals;
    using namespace scion;
    using Socket = posix::IpUdpSocket;

    Socket s;
    if (auto ec = s.bind(bind, ports.first, ports.second); ec) {
        std::cerr << "Can't bind to " << bind << " : " << fmtError(ec) << '\n';
        return EXIT_FAILURE;
    }
    if (auto ec = s.setRecvTimeout(100ms); ec) {
        std::cerr << "Setting receive timeout failed: " << fmtError(ec) << '\n';
        return EXIT_FAILURE;
    }

    CON_WIN32(HANDLE hConsoleInput = GetStdHandle(STD_INPUT_HANDLE));
    CON_CURSES(ncurses::initServer());

    std::stringstream stream;
    stream << "Server listening at " << s.localEp() << '\n';
    stream << "Press q to quit.\n";
    CON_WIN32(std::cout << stream.str());
    CON_CURSES(ncurses::print(stream.str().c_str()));

    Socket::Endpoint from;
    Socket::UnderlayEp ulSource;
    HeaderCache headers;
    std::vector<std::byte> buffer(9000);
    auto path = std::make_unique<RawPath>();

    CON_WIN32(while (!isKeyPressed(hConsoleInput, TCHAR('Q'))))
    CON_CURSES(while (ncurses::getChar() != 'q'))
    {
        CON_CURSES(ncurses::refreshScreen());
        auto recvd = s.recvFromVia(buffer, from, *path, ulSource);
        if (recvd.has_value()) {
            stream.str("");
            stream.clear();
            stream << "Received " << recvd->size() << " bytes from " << from << ":\n";
            stream << printBuffer(*recvd);

            if (!path->reverseInPlace()) {
                if (args.show_path) stream << "Path: " << *path << '\n';
                (void)s.sendTo(headers, from, *path, ulSource, *recvd);
            }

            CON_WIN32(std::cout << stream.str());
            CON_CURSES(ncurses::print(stream.str().c_str()));
        } else if (recvd.error() != ErrorCondition::WouldBlock) {
            CON_CURSES(ncurses::endServer());
            std::cerr << "Error: " << fmtError(recvd.error()) << '\n';
            return EXIT_FAILURE;
        }
    }
    CON_CURSES(ncurses::endServer());
    return EXIT_SUCCESS;
}

int runClient(
    scion::daemon::GrpcDaemonClient& sciond,
    const scion::posix::IpUdpSocket::Endpoint& bind,
    std::pair<uint16_t, uint16_t> ports,
    Arguments& args)
{
    using namespace std::chrono_literals;
    using namespace scion;
    using Socket = posix::IpUdpSocket;

    auto remote = scion::posix::IpUdpSocket::Endpoint::Parse(args.remoteAddr);
    if (isError(remote)) {
        std::cerr << "Invalid destination address: " << args.remoteAddr << '\n';
        return EXIT_FAILURE;
    }

    PathCache pool;
    auto queryPaths = [&sciond] (PathCache& cache, IsdAsn src, IsdAsn dst) -> std::error_code {
        using namespace daemon;
        std::vector<PathPtr> paths;
        auto flags = PathReqFlags::Refresh | PathReqFlags::AllMetadata;
        sciond.rpcPaths(src, dst, flags, std::back_inserter(paths));
        cache.store(src, dst, paths);
        return ErrorCode::Ok;
    };

    auto paths = pool.lookup(bind.isdAsn(), remote->isdAsn(), queryPaths);
    if (isError(paths) || paths->empty()) {
        std::cerr << "No path to " << remote->isdAsn() << '\n';
        return EXIT_FAILURE;
    }

    Socket s;
    s.setNextScmpHandler(&pool);
    if (auto ec = s.bind(bind, ports.first, ports.second); ec) {
        std::cerr << "Can't bind to " << bind << " : " << fmtError(ec) << '\n';
        return EXIT_FAILURE;
    }
    s.connect(*remote);
    if (auto ec = s.setRecvTimeout(100ms); ec) {
        std::cerr << "Setting receive timeout failed: " << fmtError(ec) << '\n';
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
    auto nextHop = path->nextHop(remote->localEp());
    auto underlayDst = toUnderlay<Socket::UnderlayEp>(nextHop).value();

    if (args.stun) {
        auto stunServer = toUnderlay<Socket::UnderlayEp>(
            generic::IPEndpoint(nextHop.host(), 3478)).value();
        if (auto mapped = getStunMapping(s, stunServer, 100ms); mapped) {
            std::cerr << "SNAT mapped address: " << mapped->localEp() << '\n';
        } else {
            std::cerr << "Can't get SNAT address mapping: " << fmtError(mapped.error()) << '\n';
        }
    }

    Socket::Endpoint from;
    HeaderCache headers;
    std::vector<std::byte> sendBuffer, recvBuffer;
    if (args.message.empty()) args.message = "Hello!";
    sendBuffer.reserve(args.message.size());
    std::ranges::transform(args.message, std::back_inserter(sendBuffer), [] (char c) {
        return std::byte{(unsigned char)c};
    });
    recvBuffer.resize(2048);
    for (int i = 0; i < args.count; ++i) {
        auto sent = s.send(headers, *path, underlayDst, sendBuffer);
        if (isError(sent)) {
            std::cerr << "Error: " << fmtError(sent.error()) << '\n';
            return EXIT_FAILURE;
        }

        auto recvd = s.recvFrom(recvBuffer, from);
        if (isError(recvd)) {
            if (recvd.error() == ErrorCondition::WouldBlock) {
                std::cerr << "No response\n";
            } else {
                std::cerr << "Error: " << fmtError(recvd.error()) << '\n';
            }
            return EXIT_FAILURE;
        }
        if (!args.quiet) {
            std::cout << "Received " << recvd->size() << " bytes from " << from << ":\n";
            std::cout << printBuffer(*recvd);
        } else {
            printEscapedString(std::cout, *recvd);
        }
    }
    return EXIT_SUCCESS;
}
