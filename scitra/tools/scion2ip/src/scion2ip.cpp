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

#include "scion/addr/address.hpp"
#include "scion/addr/generic_ip.hpp"
#include "scion/addr/isd_asn.hpp"
#include "scion/addr/mapping.hpp"

#include <CLI/CLI.hpp>

#include <cstdint>
#include <cstdlib>
#include <format>
#include <string>

using namespace scion;
using namespace scion::generic;
using std::uint32_t;
using std::uint64_t;


struct Arguments
{
    std::string address;
    uint32_t prefix = 0;
    uint32_t subnet = 0;
    uint32_t subnetBits = 8;
    bool verbose = false;
};

uint32_t getPrefix(const IPAddress& ip, uint32_t subnetBits)
{
    auto [prefix, _] = ip.getIPv6();
    return (uint32_t)((prefix >> subnetBits) & ~(~0ull << (24 - subnetBits)));
}

uint32_t getSubnet(const IPAddress& ip, uint32_t subnetBits)
{
    auto [prefix, _] = ip.getIPv6();
    return (uint32_t)(prefix & ~(~0ull << subnetBits));
}

IPAddress setPrefix(
    const IPAddress& ip, uint32_t localPrefix, uint32_t subnetBits)
{
    auto [prefix, host] = ip.getIPv6();
    auto mask = (~0ull << (24 - subnetBits)) | ~(~0ull << subnetBits);
    prefix = (prefix & mask) | (localPrefix << subnetBits);
    return IPAddress::MakeIPv6(prefix, host);
}

IPAddress setSubnet(
    const IPAddress& ip, uint32_t subnet, uint32_t subnetBits)
{
    auto [prefix, host] = ip.getIPv6();
    prefix = (prefix & (~0ull << subnetBits)) | subnet;
    return IPAddress::MakeIPv6(prefix, host);
}

Maybe<IPAddress> mapToIPv6(IsdAsn isdAsn, const IPAddress& ip)
{
    auto [prefix, host] = ip.getIPv6();
    if (prefix >> 24) {
        // there is already a prefix in teh first 40 bits
        return Error(ErrorCode::InvalidArgument);
    }

    uint64_t isd = isdAsn.isd();
    if (!(isd < (1 << 12))) return Error(ErrorCode::InvalidArgument);

    uint64_t asn = isdAsn.asn();
    uint64_t encodedAsn = 0;
    if (asn < (1ull << 19)) {
        encodedAsn = asn;
    } else if (0x2'0000'0000ull <= asn && asn <= 0x2'0007'ffffull) {
        encodedAsn = (1ull << 19) | (asn & 0x7ffffull);
    } else {
        return Error(ErrorCode::InvalidArgument);
    }

    prefix = SCION_IP_PREFIX | (isd << 44) | (encodedAsn << 24) | prefix;
    return IPAddress::MakeIPv6(prefix, host);
}

int main(int argc, char* argv[])
{
    Arguments args;
    CLI::App app{"Map SCION to IPv6 address and vice versa."};
    app.add_option("address", args.address, "SCION address or SCION-mapped IPv6")
        ->required();
    app.add_option("-p,--prefix", args.prefix, "AS-local routing prefix for SCION-IPv6 in IPv6");
    app.add_option("-s,--subnet", args.subnet, "Local subnet for SCION-IPv6 in IPv6");
    app.add_option("-l,--subnet-bits", args.subnetBits, "Length of the subnet ID (default: 8)")
        ->check(CLI::Range(24));
    app.add_flag("-v,--verbose", args.verbose,
        "Print extracted local prefix and subnet in addition to translated address");
    CLI11_PARSE(app, argc, argv);

    if (args.prefix) {
        if (args.prefix >= (1u << (24 - args.subnetBits))) {
            std::cerr << "Invalid prefix" << std::endl;
            return EXIT_FAILURE;
        }
    }
    if (args.subnet) {
        if (args.subnet >= (1u << args.subnetBits)) {
            std::cerr << "Invalid subnet" << std::endl;
            return EXIT_FAILURE;
        }
    }

    // SCION to IP
    if (auto sci = scion::ScIPAddress::Parse(args.address); sci) {
        auto host = sci->host().unmap4in6();
        if (host.is6()) {
            if (args.prefix)
                host = setPrefix(host, args.prefix, args.subnetBits);
            if (args.subnet)
                host = setSubnet(host, args.subnet, args.subnetBits);
        }
        Maybe<IPAddress> ip;
        if (host.is4() || host.isScion()) {
            ip = mapToIPv6(ScIPAddress(sci->isdAsn(), host));
        } else {
            ip = mapToIPv6(sci->isdAsn(), host);
        }
        if (isError(ip)) {
            std::cerr << args.address << " cannot be mapped to an IPv6 address" << std::endl;
            return EXIT_FAILURE;
        }
        std::cout << *ip << std::endl;
        return EXIT_SUCCESS;
    }

    // IP to SCION
    if (auto ip = IPAddress::Parse(args.address); ip) {
        auto sci = unmapFromIPv6(*ip);
        if (isError(sci)) {
            std::cerr << args.address << " is not a SCION-mapped IPv4" << std::endl;
            return EXIT_FAILURE;
        }
        std::cout << *sci;
        if (args.verbose) {
            std::cout << std::format(" 0x{:x} 0x{:x}",
                getPrefix(sci->host(), args.subnetBits),
                getSubnet(sci->host(), args.subnetBits));
        }
        std::cout << std::endl;
        return EXIT_SUCCESS;
    }

    std::cerr << args.address << " not recognized as an address" << std::endl;
    return EXIT_FAILURE;
}
