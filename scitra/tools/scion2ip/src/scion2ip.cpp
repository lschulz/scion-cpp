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


extern const char* VERSION_LINE;

struct Arguments
{
    std::string address;
    uint32_t prefix = 0;
    uint32_t subnet = 0;
    uint32_t subnetBits = 8;
    bool describe = false;
    bool verbose = false;
};

uint32_t getPrefix(const IPAddress& ip, uint32_t prefixLen, uint32_t subnetBits)
{
    auto [prefix, _] = ip.getIPv6();
    return (uint32_t)((prefix >> subnetBits) & ~(~0ull << (prefixLen - subnetBits)));
}

uint32_t getSubnet(const IPAddress& ip, uint32_t subnetBits)
{
    auto [prefix, _] = ip.getIPv6();
    return (uint32_t)(prefix & ~(~0ull << subnetBits));
}

IPAddress setPrefix(
    const IPAddress& ip, uint32_t localPrefix, uint32_t prefixLen, uint32_t subnetBits)
{
    auto [prefix, host] = ip.getIPv6();
    auto mask = (~0ull << (prefixLen - subnetBits)) | ~(~0ull << subnetBits);
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
    auto [ipPrefix, host] = ip.getIPv6();
    uint64_t isd = isdAsn.isd();
    if (!(isd < (1 << 12))) return Error(ErrorCode::InvalidArgument);

    uint64_t asn = isdAsn.asn();
    std::uint64_t prefix = 0;
    if (asn < (1ull << 19)) {
        if (prefix >> 24) return Error(ErrorCode::InvalidArgument);
        prefix = SCION_IP_PREFIX | (isd << 44) | (asn << 24) | (ipPrefix & ~(~0 << 24));
    } else if (0x2'0000'0000ull <= asn && asn <= 0x2'ffff'ffffull) {
        if (prefix >> 8) return Error(ErrorCode::InvalidArgument);
        prefix = SCION_IP_PREFIX | (isd << 44) | (0xeull << 40) | ((asn & 0xffff'ffff) << 8)
            | (ipPrefix & 0xff);
    } else {
        return Error(ErrorCode::InvalidArgument);
    }
    return IPAddress::MakeIPv6(prefix, host);
}

const char* toString(scion::ScionIPv6Class type)
{
    using namespace scion;
    switch (type) {
    default:
    case ScionIPv6Class::INVALID:
        return "Not a SCION-mapped IPv6 address";
    case ScionIPv6Class::BGP_IPV4:
        return "19-bit BGP ASN with IPv4 host address";
    case ScionIPv6Class::BGP_IPV6:
        return "19-bit BGP ASN with 24-bit local prefix and 64-bit interface ID";
    case ScionIPv6Class::BGP_WILDCARD:
        return "19-bit BGP ASN with 24-bit local prefix and no host address";
    case ScionIPv6Class::WILDCARD_ASN:
        return "Wildcard ASN";
    case ScionIPv6Class::PUBLIC_SCION_IPV4:
        return "32-bit SCION ASN between 2:0:0 and 2:ffff:ffff with IPv4 host address";
    case ScionIPv6Class::PUBLIC_SCION_IPV6:
        return "32-bit SCION ASN between 2:0:0 and 2:ffff:ffff with 8-bit local prefix"
            " and 64-bit interface ID";
    case ScionIPv6Class::PUBLIC_SCION_WILDCARD:
        return "32-bit SCION ASN between 2:0:0 and 2:ffff:ffff with no host address";
    case ScionIPv6Class::RESERVED:
        return "Reserved SCION-mapped IPv6 address";
    }
}

int setPrefixAndSubnet(Arguments& args, uint32_t prefixLen, scion::generic::IPAddress& host)
{
    if (args.subnetBits > 24) {
        std::cerr << "invalid subnet length\n";
        return EXIT_FAILURE;
    }
    if (args.prefix) {
        if (args.prefix >= (1u << (prefixLen - args.subnetBits))) {
            std::cerr << "invalid local prefix\n";
            return EXIT_FAILURE;
        }
        host = setPrefix(host, args.prefix, prefixLen, args.subnetBits);
    }
    if (args.subnet) {
        if (args.subnet >= (1u << args.subnetBits)) {
            std::cerr << "invalid subnet\n";
            return EXIT_FAILURE;
        }
        host = setSubnet(host, args.subnet, args.subnetBits);
    }
    return 0;
}

int main(int argc, char* argv[])
{
    Arguments args;
    CLI::App app{"Map SCION to IPv6 address and vice versa."};
    app.add_option("address", args.address, "SCION address or SCION-mapped IPv6")
        ->required();
    app.add_option("-p,--prefix", args.prefix, "AS-local routing prefix for SCION-IPv6 in IPv6");
    app.add_option("-s,--subnet", args.subnet, "Local subnet for SCION-IPv6 in IPv6");
    app.add_option("-l,--subnet-bits", args.subnetBits, "Length of the subnet ID (default: 8)");
    app.add_flag("-d,--describe", args.describe,
        "Instead of printing the translated address, describe the format of SCION-mapped IPv6"
        " this address is an example of.");
    app.add_flag("-v,--verbose", args.verbose,
        "Print extracted local prefix and subnet in addition to translated address");
    app.set_version_flag("-V,--version", VERSION_LINE);
    CLI11_PARSE(app, argc, argv);

    // SCION to IP
    if (auto sci = scion::ScIPAddress::Parse(args.address); sci) {
        auto host = sci->host().unmap4in6();
        if (host.is6()) {
            auto asn = sci->isdAsn().asn();
            if (asn < (1ull << 19)) {
                auto err = setPrefixAndSubnet(args, 24, host);
                if (err) return err;
            } else if (0x2'0000'0000ull <= asn && asn <= 0x2'ffff'ffffull) {
                auto err = setPrefixAndSubnet(args, 8, host);
                if (err) return err;
            }
        }
        Maybe<IPAddress> ip;
        if (host.is4() || host.isScion()) {
            ip = mapToIPv6(ScIPAddress(sci->isdAsn(), host));
        } else {
            ip = mapToIPv6(sci->isdAsn(), host);
        }
        if (isError(ip)) {
            std::cerr << args.address << " cannot be mapped to an IPv6 address\n";
            return EXIT_FAILURE;
        }
        if (args.describe) {
            std::cout << toString(scion::classifyScionMappedIP(*ip)) << '\n';
            return EXIT_SUCCESS;
        }
        std::cout << *ip << '\n';
        return EXIT_SUCCESS;
    }

    // IP to SCION
    if (auto ip = IPAddress::Parse(args.address); ip) {
        if (args.describe) {
            std::cout << toString(scion::classifyScionMappedIP(*ip)) << '\n';
            return EXIT_SUCCESS;
        }
        auto sci = unmapFromIPv6(*ip);
        if (isError(sci)) {
            std::cerr << args.address << " is not a SCION-mapped IPv4\n";
            return EXIT_FAILURE;
        }
        std::cout << *sci;
        if (args.verbose) {
            switch (scion::classifyScionMappedIP(*ip)) {
            case ScionIPv6Class::BGP_IPV4:
            case ScionIPv6Class::BGP_IPV6:
            case ScionIPv6Class::BGP_WILDCARD:
                if (args.subnetBits > 24) {
                    std::cerr << " invalid subnet length\n";
                    return EXIT_FAILURE;
                }
                std::cout << std::format(" 0x{:x} 0x{:x}",
                    getPrefix(sci->host(), 24, args.subnetBits),
                    getSubnet(sci->host(), args.subnetBits));
                break;
            case ScionIPv6Class::PUBLIC_SCION_IPV4:
            case ScionIPv6Class::PUBLIC_SCION_IPV6:
            case ScionIPv6Class::PUBLIC_SCION_WILDCARD:
                if (args.subnetBits > 8) {
                    std::cerr << " invalid subnet length\n";
                    return EXIT_FAILURE;
                }
                std::cout << std::format(" 0x{:x} 0x{:x}",
                    getPrefix(sci->host(), 8, args.subnetBits),
                    getSubnet(sci->host(), args.subnetBits));
                break;
            default:
                break;
            }

        }
        std::cout << '\n';
        return EXIT_SUCCESS;
    }

    std::cerr << args.address << " not recognized as an address\n";
    return EXIT_FAILURE;
}
