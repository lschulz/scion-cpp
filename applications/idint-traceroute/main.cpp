// Copyright (c) 2026 Lars-Christian Schulz
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

#include "config.hpp"
#include "idint_traceroute.hpp"
#include "tables.hpp"

#include <CLI/CLI.hpp>
#include <scion/addr/generic_ip.hpp>
#include <scion/extensions/idint_instr.hpp>

#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <format>
#include <iostream>
#include <string_view>
#include <string>

using namespace scion;


static void parseAgrMode(std::string_view sv, idint::AM& dst)
{
    auto i = std::ranges::find(IdIntAgrModeTable, sv, [](const auto& x) {
        return x.first;
    });
    if (i == IdIntAgrModeTable.end()) {
        throw CLI::ConversionError(std::format("Mode \"{}\" not recognized", sv));
    }
    dst = i->second;
}

static void parseAgrFunc(std::string_view sv, idint::AF& dst)
{
    auto i = std::ranges::find(IdIntAgrFuncTable, sv, [](const auto& x) {
        return x.first;
    });
    if (i == IdIntAgrFuncTable.end()) {
        throw CLI::ConversionError(std::format("Function \"{}\" not recognized", sv));
    }
    dst = i->second;
}

static void parseInstruction(std::string_view sv, idint::Instr& dst)
{
    auto i = std::ranges::find(IdIntInstructionTable, sv, [](const auto& x) {
        return x.first;
    });
    if (i == IdIntInstructionTable.end()) {
        throw CLI::ConversionError(std::format("Instruction \"{}\" not recognized", sv));
    }
    dst = i->second;
}

static int parseArgs(int argc, char* argv[], Config &cfg)
{
    CLI::App app("ID-INT Traceroute Client/Server");
    std::string local, remote;

    // Global options
    app.add_option("-d,--sciond", cfg.sciond,
        "SCION daemon address (default \"127.0.0.1:30255\")")
        ->envname("SCION_DAEMON_ADDRESS");
    app.add_option_function<std::string_view>("-l,--local", [&](std::string_view sv) {
        if (auto ep = generic::IPEndpoint::Parse(sv); ep) {
            cfg.local = *ep;
        } else {
            throw CLI::ConversionError(
                std::format("Cannot parse address \"{}\": {}", sv, fmtError(ep.error())));
        }
    }, "Local IP address and port (required for servers)");
    app.require_subcommand(1);

    // Server-specific options
    auto server = app.add_subcommand("server", "Run as server")
        ->preparse_callback([&](std::size_t n) {
            cfg.serverMode = true;
        });
    server->add_flag("-v,--verbose", cfg.server.verbose,
        "Print status information when responding to a packet");

    // Client-specific options
    auto client = app.add_subcommand("client", "Run as client")
        ->preparse_callback([&](std::size_t n) {
            cfg.serverMode = false;
        });
    client->add_option_function<std::string_view>("remote", [&](std::string_view sv) {
        if (auto ep = ScIPEndpoint::Parse(sv); ep) {
            cfg.client.remote = *ep;
        } else {
            throw CLI::ConversionError(
                std::format("Cannot parse address \"{}\": {}", sv, fmtError(ep.error())));
        }
    }, "SCION address of the destination. Must include a port.")->required();
    client->add_option("--stun", cfg.client.stun, "Attempt NAT traversal");
    client->add_option("-t,--timeout", cfg.client.timeout, "Receive timeput in seconds.");
    client->add_option("-n,--period", cfg.client.period,
        "Update period if polling continuously in seconds.");
    client->add_option("-s,--skip", cfg.client.skip, "Skip telemetry of the first n hops");
    client->add_option("-l,--limit", cfg.client.limit, "Allocated maximum telemetry stack size");
    client->add_option_function<std::string_view>("-a,--agr-mode", [&](std::string_view sv) {
        parseAgrMode(sv, cfg.client.agrMode);
    }, "Aggregation mode");
    client->add_flag("-p,--path", cfg.client.path,
        "Index of the path to take in the same order as displayed by 'scion showpaths'")
        ->check(CLI::NonNegativeNumber);
    client->add_flag("-u,--tui", cfg.client.tui, "Run in TUI mode");

    auto crypto = client->add_option_group("Cryptography")->require_option(0, 1);
    crypto->add_flag("-n,--no-verify", cfg.client.noVerify, "Disable telemetry MAC verification");
    crypto->add_flag("-e,--encrypt", cfg.client.encrypt, "Request metadata encryption");

    auto instr = client->add_option_group("Telemetry Requests");
    instr->add_flag("--nid", cfg.client.reqNodeId, "Request node ID");
    instr->add_flag("--nc", cfg.client.reqNodeCnt, "Request aggregated node count");
    instr->add_flag("--igr", cfg.client.reqIgr, "Request ingress port");
    instr->add_flag("--egr", cfg.client.reqEgr, "Request egress port");
    instr->add_option_function<std::string_view>("-1,--instr1", [&](std::string_view sv) {
        parseInstruction(sv, cfg.client.instrs[0]);
    }, "First telemetry instruction");
    instr->add_option_function<std::string_view>("-2,--instr2", [&](std::string_view sv) {
        parseInstruction(sv, cfg.client.instrs[1]);
    }, "Second telemetry instruction");
    instr->add_option_function<std::string_view>("-3,--instr3", [&](std::string_view sv) {
        parseInstruction(sv, cfg.client.instrs[2]);
    }, "Third telemetry instruction");
    instr->add_option_function<std::string_view>("-4,--instr4", [&](std::string_view sv) {
        parseInstruction(sv, cfg.client.instrs[3]);
    }, "Fourth telemetry instruction");
    instr->add_option_function<std::string_view>("--af1", [&](std::string_view sv) {
        parseAgrFunc(sv, cfg.client.agrFuncs[0]);
    }, "First aggregation function");
    instr->add_option_function<std::string_view>("--af2", [&](std::string_view sv) {
        parseAgrFunc(sv, cfg.client.agrFuncs[1]);
    }, "Second aggregation function");
    instr->add_option_function<std::string_view>("--af3", [&](std::string_view sv) {
        parseAgrFunc(sv, cfg.client.agrFuncs[2]);
    }, "Third aggregation function");
    instr->add_option_function<std::string_view>("--af4", [&](std::string_view sv) {
        parseAgrFunc(sv, cfg.client.agrFuncs[3]);
    }, "Fourth aggregation function");

    CLI11_PARSE(app, argc, argv);
    return 0;
}

int main(int argc, char* argv[])
{
    static Config cfg;
    if (int ret = parseArgs(argc, argv, cfg); ret) {
        return ret;
    }
    if (cfg.serverMode) {
        Server s(cfg);
        return s.run();
    } else {
        Client c(cfg);
        return c.run();
    }
    return EXIT_SUCCESS;
}
