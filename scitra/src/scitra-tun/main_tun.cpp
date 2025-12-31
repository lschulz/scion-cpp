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

#include "scitra/scitra-tun/cli_args.hpp"
#include "scitra/scitra-tun/scitra_tun.hpp"
#include "scitra/scitra-tun/sys_net.hpp"

#include <spdlog/spdlog.h>
#include <spdlog/sinks/basic_file_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/sinks/stdout_sinks.h>

#include <sys/capability.h>

#include <iostream>
#include <memory>
#include <ranges>
#include <signal.h>
#include <system_error>


extern const char* VERSION_LINE;

static std::unique_ptr<Arguments> parseCommandLine(int argc, char* argv[])
{
    auto args = std::make_unique<Arguments>();
    CLI::App app{"scitra-tun: SCION-IP Translator for Linux"};
    app.add_option("public_interface,--interface", args->publicInterface,
        "Main network interface through which other SCION hosts can be reached")
        ->required();
    app.add_option("public_address,--address", args->publicAddress,
        "IP address for SCION. Must either be an IPv4 or SCION-mapped IPv6 address.")
        ->required();
    app.add_option("-d,--sciond", args->sciond,
        "SCION daemon address (default \"127.0.0.1:30255\")")
        ->envname("SCION_DAEMON_ADDRESS");
    app.add_option("-n,--tun-name", args->tunDevice,
        "Name of the TUN device created by scitra-tun (default \"scion\")");
    app.add_option("-a,--tun-addr", args->tunAddress,
        "Override the address assigned to the TUN device with another IPv6"
        " address. By default, the TUN address is derived from the public"
        " address.");
    app.add_option("-m,--mtu", args->tunMtu,
        "Override the default MTU of the TUN interface.");
    app.add_option("-p,--ports", args->ports,
        "One ore mote statically forwarded TCP/UDP ports separated by whitespace.");
    app.add_option("-q,--queues", args->queues,
        "Number of TUN queues and threads (default 1)")
        ->check(CLI::Range(1, 64));
    app.add_option("-t,--threads", args->threads,
        "Number of socket worker threads (default 1)")
        ->check(CLI::Range(1, 64));
    app.add_option("--policy", args->policy,
        "Path to a JSON file containing path policies");
    app.add_option("-l,--log-file", args->logFile,
        "Path to log file. Log is written to stderr if this option is not given.");
    app.add_flag("--scmp", args->enableScmpDispatch,
        "Accept SCMP packets at the endhost/dispatcher port (30041/UDP)");
    app.add_flag("--stun", args->stun, "Attempt NAT traversal");
    app.add_option("--stun-port", args->stunPort,
        "Port at which STUN servers are expected. If set to zero uses the same port as for SCION"
        " (default 3478)");
    app.add_option("--nat-timeout", args->stunTimeout,
        "Timeout for NAT bindings. That is, after how many seconds of inactivity a STUN request"
        " must be repeated. (default 30)");
    app.add_flag("--tui", args->tui, "Start with TUI");
    app.set_version_flag("-v,--version", VERSION_LINE);
    app.set_config("--config", "",
        "Configuration file containing command line options in ini or TOML syntax.");
    try {
        app.parse(argc, argv);
        std::ranges::sort(args->ports);
        return args;
    }
    catch (const CLI::ParseError& e) {
        std::exit(app.exit(e));
    }
}

static void blockSignals()
{
    sigset_t sigset;
    sigfillset(&sigset);
    sigdelset(&sigset, SIGWINCH);
    if (pthread_sigmask(SIG_BLOCK, &sigset, nullptr))
        throw std::system_error(errno, std::generic_category());
}

// Drop all effective, permitted and inheritable capabilites except for
// CAP_NET_BIND_SERVICE. CAP_NET_BIND_SERVICE is needed to bind SCION sockets
// to privileged ports < 1024.
static int dropCapabilities() noexcept
{
    auto caps = cap_get_proc();
    if (caps == NULL) return -1;

    cap_flag_value_t netBindCap;
    if (cap_get_flag(caps, CAP_NET_BIND_SERVICE, CAP_PERMITTED, &netBindCap) == -1) {
        cap_free(caps);
        return -1;
    }
    if (cap_clear(caps) == -1) {
        cap_free(caps);
        return -1;
    }
    if (netBindCap == CAP_SET) {
        const cap_value_t setCaps[] = {CAP_NET_BIND_SERVICE};
        if (cap_set_flag(caps, CAP_PERMITTED, 1, setCaps, CAP_SET) == -1) {
            cap_free(caps);
            return -1;
        }
        if (cap_set_flag(caps, CAP_EFFECTIVE, 1, setCaps, CAP_SET) == -1) {
            cap_free(caps);
            return -1;
        }
    }

    int res = cap_set_proc(caps);
    cap_free(caps);
    return res;
}

void uiLoop(ScitraTun& app);

int main(int argc, char* argv[])
{
    auto args = parseCommandLine(argc, argv);
    try {
        if (args->logFile.empty()) {
            if (args->tui)
                spdlog::set_default_logger(spdlog::stderr_logger_mt("log"));
            else
                spdlog::set_default_logger(spdlog::stderr_color_mt("log"));
        } else {
            spdlog::set_default_logger(spdlog::basic_logger_mt("log", args->logFile));
        }
        spdlog::set_pattern("[%Y-%m-%d %T.%e] [%t] [%^%l%$] %v");
        spdlog::flush_on(spdlog::level::info);
    }
    catch (const spdlog::spdlog_ex& e) {
        std::cerr << "Log init failed: " << e.what() << std::endl;
    }

    try {
        blockSignals();
        Socket::configureStun(args->stun, args->stunPort, args->stunTimeout);

        ScitraTun app(*args);
        bool tui = args->tui;
        args.reset();

        if (dropCapabilities()) spdlog::error("dropping capabilities failed");
        app.run();
        if (tui) uiLoop(app);
        app.join();
    }
    catch (const std::exception& e) {
        spdlog::error(e.what());
        std::cerr << e.what() << std::endl;
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
