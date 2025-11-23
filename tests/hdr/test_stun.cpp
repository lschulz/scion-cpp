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

#include "scion/bit_stream.hpp"
#include "scion/hdr/stun.hpp"

#include "gtest/gtest.h"
#include "gmock/gmock.h"
#include "utilities.hpp"


TEST(STUN, Parse)
{
    using namespace scion::hdr;
    using scion::generic::IPAddress;

    auto pkts = loadPackets("hdr/data/stun.bin");

    // Binding request
    {
        scion::ReadStream stream(pkts.at(0));
        scion::StreamError err;
        STUN stun;
        ASSERT_TRUE(stun.serialize(stream, err)) << err;
        EXPECT_EQ(stun.type, StunMsgType::BindingRequest);
        EXPECT_THAT(stun.transaction, testing::ElementsAre(
            0x12_b, 0x34_b, 0x56_b, 0x78_b, 0x9a_b, 0xbc_b, 0xde_b, 0xf0_b,
            0xff_b, 0xff_b, 0x00_b, 0x0_b
        ));
    }

    // Binding success response (IPv4)
    {
        scion::ReadStream stream(pkts.at(1));
        scion::StreamError err;
        STUN stun;
        ASSERT_TRUE(stun.serialize(stream, err)) << err;
        EXPECT_EQ(stun.type, StunMsgType::BindingResponse);
        EXPECT_THAT(stun.transaction, testing::ElementsAre(
            0x12_b, 0x34_b, 0x56_b, 0x78_b, 0x9a_b, 0xbc_b, 0xde_b, 0xf0_b,
            0xff_b, 0xff_b, 0x00_b, 0x0_b
        ));
        ASSERT_TRUE(stun.mapped.has_value());
        EXPECT_EQ(stun.mapped->address.port(), 53794);
        EXPECT_EQ(stun.mapped->address.host(), unwrap(IPAddress::Parse("192.0.2.1")));
    }

    // Binding success response (IPv6)
    {
        scion::ReadStream stream(pkts.at(2));
        scion::StreamError err;
        STUN stun;
        ASSERT_TRUE(stun.serialize(stream, err)) << err;
        EXPECT_EQ(stun.type, StunMsgType::BindingResponse);
        EXPECT_THAT(stun.transaction, testing::ElementsAre(
            0x12_b, 0x34_b, 0x56_b, 0x78_b, 0x9a_b, 0xbc_b, 0xde_b, 0xf0_b,
            0xff_b, 0xff_b, 0x00_b, 0x0_b
        ));
        ASSERT_TRUE(stun.mapped.has_value());
        EXPECT_EQ(stun.mapped->address.port(), 53794);
        EXPECT_EQ(stun.mapped->address.host(), unwrap(IPAddress::Parse("2001:db8::1")));
    }
}

TEST(STUN, Emit)
{
    using namespace scion::hdr;
    using scion::generic::IPEndpoint;

    auto pkts = loadPackets("hdr/data/stun_expected.bin");

    // Binding request
    {
        auto& expected = pkts.at(0);
        std::vector<std::byte> buffer(expected.size());
        scion::WriteStream stream(buffer);
        scion::StreamError err;

        STUN stun;
        stun.type = StunMsgType::BindingRequest;
        stun.transaction = {
            0x12_b, 0x34_b, 0x56_b, 0x78_b, 0x9a_b, 0xbc_b, 0xde_b, 0xf0_b,
            0xff_b, 0xff_b, 0x00_b, 0x0_b
        };

        ASSERT_TRUE(stun.serialize(stream, err)) << err;
        EXPECT_EQ(buffer, expected) << printBufferDiff(buffer, expected);
    }

    // Binding success response (IPv4)
    {
        auto& expected = pkts.at(1);
        std::vector<std::byte> buffer(expected.size());
        scion::WriteStream stream(buffer);
        scion::StreamError err;

        STUN stun;
        stun.type = StunMsgType::BindingResponse;
        stun.transaction = {
            0x12_b, 0x34_b, 0x56_b, 0x78_b, 0x9a_b, 0xbc_b, 0xde_b, 0xf0_b,
            0xff_b, 0xff_b, 0x00_b, 0x0_b
        };
        stun.mapped = StunXorMappedAddress{
            .address = unwrap(IPEndpoint::Parse("192.0.2.1:53794"))
        };

        ASSERT_TRUE(stun.serialize(stream, err)) << err;
        EXPECT_EQ(buffer, expected) << printBufferDiff(buffer, expected);
    }

    // Binding success response (IPv6)
    {
        auto& expected = pkts.at(2);
        std::vector<std::byte> buffer(expected.size());
        scion::WriteStream stream(buffer);
        scion::StreamError err;

        STUN stun;
        stun.type = StunMsgType::BindingResponse;
        stun.transaction = {
            0x12_b, 0x34_b, 0x56_b, 0x78_b, 0x9a_b, 0xbc_b, 0xde_b, 0xf0_b,
            0xff_b, 0xff_b, 0x00_b, 0x0_b
        };
        stun.mapped = StunXorMappedAddress{
            .address = unwrap(IPEndpoint::Parse("[2001:db8::1]:53794"))
        };

        ASSERT_TRUE(stun.serialize(stream, err)) << err;
        EXPECT_EQ(buffer, expected) << printBufferDiff(buffer, expected);
    }
}

TEST(STUN, Print)
{
    using namespace scion::hdr;
    using scion::generic::IPEndpoint;

    STUN stun;
    stun.type = StunMsgType::BindingResponse;
    stun.transaction = {
        0x12_b, 0x34_b, 0x56_b, 0x78_b, 0x9a_b, 0xbc_b, 0xde_b, 0xf0_b,
        0xff_b, 0xff_b, 0x00_b, 0x0_b
    };
    stun.mapped = StunXorMappedAddress{
        .address = unwrap(IPEndpoint::Parse("192.0.2.1:53794"))
    };

    static const char* expected =
        "###[ STUN ]###\n"
        "type        = 257\n"
        "transaction = 12:34:56:78:9a:bc:de:f0:ff:ff:00:00\n"
        "xor mapped  = 192.0.2.1:53794\n";

    std::string str;
    str.reserve(std::strlen(expected));
    std::back_insert_iterator out(str);
    out = stun.print(out, 0);
    EXPECT_EQ(str, expected);
}

TEST(STUN, PrintAttributes)
{
    using namespace scion::hdr;
    using scion::generic::IPEndpoint;

    StunAttribute attrib = {
        .type = StunAttribType::MappedAddress,
        .length = 8,
        .value = {
            0x00_b, 0x01_b, 0xd2_b, 0x22_b, 0xc0_b, 0x00_b, 0x02_b, 0x01_b
        }
    };
    StunXorMappedAddress xorAddr = {
        .address = unwrap(IPEndpoint::Parse("192.0.2.1:53794"))
    };

    static const char* expected =
        "###[ STUN Generic TLV ]###\n"
        "type   = 1\n"
        "length = 8\n"
        "value  = 00:01:d2:22:c0:00:02:01\n"
        "###[ STUN XOR-MAPPED-ADDRESS ]###\n"
        "type    = 32\n"
        "length  = 8\n"
        "port    = 53794\n"
        "address = 192.0.2.1\n";

    std::string str;
    str.reserve(std::strlen(expected));
    std::back_insert_iterator out(str);
    out = attrib.print(out, 0);
    out = xorAddr.print(out, 0);
    EXPECT_EQ(str, expected);
}
