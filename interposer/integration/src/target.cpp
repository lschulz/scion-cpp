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

#include <boost/asio.hpp>
#include <CLI/CLI.hpp>

#include <array>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <format>
#include <ranges>
#include <thread>
#include <vector>


static const std::uint16_t DEFAULT_PORT = 3170;

struct Arguments
{
    std::string bindAddr;
    std::string bindPort;
    std::string destAddr;
    std::string destPort = std::format("{}", DEFAULT_PORT);
    bool tcp = false;
    bool server = false;
};

int runUdpServer(const Arguments& args);
int runUdpClient(const Arguments& args);
int runTcpServer(const Arguments& args);
int runTcpClient(const Arguments& args);

int main(int argc, char* argv[])
{
    Arguments args;
    CLI::App app{"Test target program for SCION interposer"};
    app.add_option("destination", args.destAddr, "Destination address. Can be a DNS name.");
    app.add_option("port", args.destPort, "Destination port");
    app.add_option("-b,--bind", args.bindAddr, "Bind address");
    app.add_option("-p", args.bindPort, "Bind port");
    app.add_flag("-t,--tcp", args.tcp, "Use TCP instead of UDP");
    app.add_flag("-s,--server", args.server, "Run as a serve instead of as client."
        " Optional bind address and port can be given with the -b and -p option"
        " or as positional arguments.");
    CLI11_PARSE(app, argc, argv);

    if (args.server) {
        if (args.bindAddr.empty() && !args.destAddr.empty())
            args.bindAddr = args.destAddr;
        if (args.bindPort.empty() && !args.destPort.empty())
            args.bindPort = args.destPort;
    }
    else if (!args.server && args.destAddr.empty()) {
        std::cerr << "Running as client, but no destination given\n";
        return EXIT_FAILURE;
    }

    if (!args.tcp) {
        if (args.server)
            return runUdpServer(args);
        else
            return runUdpClient(args);
    } else {
        if (args.server)
            return runTcpServer(args);
        else
            return runTcpClient(args);
    }
}

// UDP echo server.
int runUdpServer(const Arguments& args)
{
    using namespace boost::asio::ip;
    using boost::asio::awaitable;

    boost::system::error_code ec;
    boost::asio::io_context ioCtx(1);
    udp::socket s(ioCtx);
    s.open(udp::v6());

    auto bind = make_address_v6("::");
    if (!args.bindAddr.empty()) {
        bind = make_address_v6(args.bindAddr, ec);
        if (ec) {
            std::cerr << std::format("{} is not a valid address\n", args.bindAddr);
            return EXIT_FAILURE;
        }
    }
    auto port = std::atoi(args.bindPort.c_str());
    udp::endpoint localEp(bind, (port_type)port);

    if (s.bind(localEp, ec); ec) {
        std::cerr << "Can't bind to " << bind << " : " << ec.what() << '\n';
        return EXIT_FAILURE;
    }
    std::cout << "Server listening at " << s.local_endpoint() << '\n';

    auto echo = [] (udp::socket& s) -> awaitable<void>
    {
        using boost::asio::use_awaitable;
        std::vector<char> buf;
        udp::endpoint sender;
        while (true) {
            buf.resize(2048);
            auto n = co_await s.async_receive_from(boost::asio::buffer(buf), sender, use_awaitable);
            std::cout << "Received " << n << " bytes from " << sender << '\n';
            buf.resize(n);
            co_await s.async_send_to(boost::asio::buffer(buf), sender, use_awaitable);
        }
    };
    auto futureResult = boost::asio::co_spawn(ioCtx, echo(s), boost::asio::use_future);
    ioCtx.run();
    futureResult.get();
    return EXIT_SUCCESS;
}

// TCP server that accepts multiple parallel connections.
int runTcpServer(const Arguments& args)
{
    using namespace boost::asio::ip;
    using boost::asio::awaitable;

    boost::system::error_code ec;
    boost::asio::io_context ioCtx(1);
    tcp::acceptor acceptor(ioCtx);
    acceptor.open(tcp::v6());
    boost::asio::socket_base::reuse_address reuseAddrOpt(true);
    acceptor.set_option(reuseAddrOpt);

    auto bind = make_address_v6("::");
    if (!args.bindAddr.empty()) {
        bind = make_address_v6(args.bindAddr, ec);
        if (ec) {
            std::cerr << std::format("{} is not a valid address\n", args.bindAddr);
            return EXIT_FAILURE;
        }
    }
    auto port = std::atoi(args.bindPort.c_str());
    if (acceptor.bind(tcp::endpoint(bind, (port_type)port), ec); ec) {
        std::cerr << "Can't bind to " << bind << " : " << ec.what() << '\n';
        return EXIT_FAILURE;
    }
    acceptor.listen(8, ec);
    if (ec) {
        std::cerr << "Listen failed : " << ec.what() << '\n';
        return EXIT_FAILURE;
    }
    std::cout << "Server listening at " << acceptor.local_endpoint() << '\n';

    auto accept = [] (tcp::socket s) -> awaitable<void>
    {
        using boost::asio::use_awaitable;
        std::vector<char> buf;
        try {
            while (true) {
                buf.resize(2048);
                auto n = co_await s.async_receive(boost::asio::buffer(buf), use_awaitable);
                buf.resize(n);
                co_await s.async_send(boost::asio::buffer(buf), use_awaitable);
            }
        } catch (const boost::system::system_error& e) {
            if (e.code() != boost::asio::error::eof)
                std::cerr << "Error: " << e.what() << '\n';
            co_return;
        }
    };

    auto listen = [&] (tcp::acceptor& acceptor) -> awaitable<void>
    {
        using boost::asio::use_awaitable;
        using boost::asio::detached;
        while (true) {
            tcp::socket s(ioCtx);
            tcp::endpoint from;
            co_await acceptor.async_accept(s, from, use_awaitable);
            std::cout << "Accepted connection from " << from << '\n';
            boost::asio::co_spawn(ioCtx, accept(std::move(s)), detached);
        }
    };

    boost::asio::signal_set signals(ioCtx, SIGINT, SIGTERM);
    signals.async_wait([&] (auto, auto) {
        ioCtx.stop();
    });
    boost::asio::co_spawn(ioCtx, listen(acceptor), boost::asio::detached);
    ioCtx.run();
    return EXIT_SUCCESS;
}

// Connect to a server.
template <typename Socket>
int connect(boost::asio::io_context& ioCtx, Socket& s, const Arguments& args)
{
    using namespace boost::asio::ip;
    boost::system::error_code ec;

    s.open(Socket::protocol_type::v6());

    if (!args.bindAddr.empty() || !args.bindPort.empty()) {
        auto bind = make_address_v6("::");
        if (!args.bindAddr.empty()) {
            bind = make_address_v6(args.bindAddr, ec);
            if (ec) {
                std::cerr << std::format("{} is not a valid address\n", args.bindAddr);
                return EXIT_FAILURE;
            }
        }
        auto port = DEFAULT_PORT;
        if (!args.bindPort.empty()) {
            port = (std::uint16_t)std::atoi(args.bindPort.c_str());
        }
        typename Socket::endpoint_type localEp(bind, port);
        if (s.bind(localEp, ec); ec) {
            std::cerr << "Can't bind to [" << bind << "]:" << port << " : " << ec << '\n';
            return EXIT_FAILURE;
        }
    }

    typename Socket::protocol_type::resolver resolver(ioCtx);
    auto res = resolver.resolve(Socket::protocol_type::v6(), args.destAddr, args.destPort, ec);
    if (ec) {
        std::cerr << std::format("Cant't resolve [{}]:{} : {}",
            args.destAddr, args.destPort, ec.what());
        return EXIT_FAILURE;
    }
    std::cerr << std::format("{} resolves to {} endpoints\n", args.destAddr, res.size());
    for (auto& dest : res) {
        s.connect(dest.endpoint(), ec);
        if (!ec) break;
        std::cerr << "Cant't connect to " << dest.endpoint() << " : " << ec.what() << '\n';
    }
    if (ec) {
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}

// Test the connection by sending a few packets.
template <typename Socket>
int testConnection(boost::asio::io_context& ioCtx, Socket& s)
{
    try {
        using namespace std::ranges;

        std::vector<char> buf(2028);
        static const std::vector<char> msg1 = {};
        static const std::vector<char> msg2 = {'T', 'E', 'S', 'T'};
        std::vector<char> msg3(1150);
        generate(msg3, [] () -> char {
            return (char)std::rand();
        });

        static const std::array<const char*, 3> titles = {
            "Empty message", "Small message", "Large message"
        };
        static const std::array<decltype(msg1), 3> msgs = {
            msg1, msg2, msg3
        };

        boost::asio::steady_timer timer(ioCtx);
        auto run = [&] (Socket& s) -> boost::asio::awaitable<int>
        {
            using namespace std::chrono_literals;
            constexpr auto use_awaitable = boost::asio::use_awaitable;
            int result = EXIT_SUCCESS;

            // give up after 1 second
            timer.expires_after(1s);
            timer.async_wait([&] (boost::system::error_code) { s.close(); });

            for (auto [title, msg] : zip_view(titles, msgs)) {
                std::cout << title << ": ";
                co_await s.async_send(boost::asio::buffer(msg), use_awaitable);
                auto n = co_await s.async_receive(boost::asio::buffer(buf), use_awaitable);
                if (equal(take_view(buf, n), msg)) {
                    std::cout << "OK\n";
                } else {
                    std::cout << "FAILED\n";
                    result = EXIT_FAILURE;
                }
            }
            timer.cancel();
            co_return result;
        };
        auto future = boost::asio::co_spawn(ioCtx, run(s), boost::asio::use_future);
        ioCtx.run();
        return future.get();
    }
    catch (const std::exception& e) {
        std::cout << "FAILED: " << e.what() << '\n';
        return EXIT_FAILURE;
    }
}

// Test the connection by sending a few packets.
int runUdpClient(const Arguments& args)
{
    using namespace boost::asio::ip;
    boost::asio::io_context ioCtx(1);
    udp::socket s(ioCtx);

    int ret = connect(ioCtx, s, args);
    if (ret) return ret;
    return testConnection(ioCtx, s);
}

// Test the connection by sending a few packets.
int runTcpClient(const Arguments& args)
{
    using namespace boost::asio::ip;

    boost::asio::io_context ioCtx(1);
    tcp::socket s(ioCtx);

    boost::asio::ip::tcp::v6();

    int ret = connect(ioCtx, s, args);
    if (ret) return ret;
    return testConnection(ioCtx, s);
}
