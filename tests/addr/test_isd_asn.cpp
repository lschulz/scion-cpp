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

#include "scion/addr/isd_asn.hpp"

#include "gtest/gtest.h"
#include "utilities.hpp"

#include <array>
#include <format>
#include <system_error>
#include <variant>


TEST(IsdAsAddr, Isd)
{
    using namespace scion;

    EXPECT_TRUE(Isd().isUnspecified());
    EXPECT_FALSE(Isd(1).isUnspecified());

    EXPECT_EQ(Isd(), Isd(0));
    EXPECT_LT(Isd(0), Isd(Isd::MAX_VALUE));
    std::hash<Isd> h;
    EXPECT_NE(h(Isd(0)), h(Isd(1)));

    EXPECT_EQ(Isd(0), unwrap(Isd::Parse("0")));
    EXPECT_EQ(Isd(Isd::MAX_VALUE), unwrap(Isd::Parse("65535")));

    EXPECT_TRUE(hasFailed(Isd::Parse("65556")));
    EXPECT_TRUE(hasFailed(Isd::Parse("ffff")));

    EXPECT_EQ(std::format("{}", Isd()), "0");
    EXPECT_EQ(std::format("{}", Isd(Isd::MAX_VALUE)), "65535");
    EXPECT_EQ(std::formatted_size("{}", Isd(Isd::MAX_VALUE)), 5);
}

TEST(IsdAsAddr, Asn)
{
    using namespace scion;

    EXPECT_TRUE(Asn().isUnspecified());
    EXPECT_FALSE(Asn(1).isUnspecified());

    EXPECT_EQ(Asn(), Asn(0));
    EXPECT_LT(Asn(0), Asn(Asn::MAX_VALUE));
    std::hash<Asn> h;
    EXPECT_NE(h(Asn(0)), h(Asn(1)));

    EXPECT_EQ(Asn(0), unwrap(Asn::Parse("0")));
    EXPECT_EQ(Asn(0), unwrap(Asn::Parse("0:0:0")));
    EXPECT_EQ(Asn(1), unwrap(Asn::Parse("0:0:1")));
    EXPECT_EQ(Asn(Asn::MAX_VALUE), unwrap(Asn::Parse("ffff:ffff:ffff")));
    EXPECT_EQ(Asn(Asn::MAX_VALUE), unwrap(Asn::Parse("FFFF:FFFF:FFFF")));
    EXPECT_EQ(Asn(Asn::MAX_VALUE), unwrap(Asn::Parse("281474976710655")));

    EXPECT_TRUE(hasFailed(Asn::Parse("0:0:0x0")));
    EXPECT_TRUE(hasFailed(Asn::Parse("::")));
    EXPECT_TRUE(hasFailed(Asn::Parse("0::0")));
    EXPECT_TRUE(hasFailed(Asn::Parse("0:0:0:0")));

    EXPECT_EQ(std::format("{}", Asn()), "0");
    EXPECT_EQ(std::format("{}", Asn(Asn::MAX_BGP_VALUE)), "4294967295");
    EXPECT_EQ(std::format("{}", Asn(Asn::MAX_BGP_VALUE + 1)), "1:0:0");
    EXPECT_EQ(std::formatted_size("{}", Asn(Asn::MAX_BGP_VALUE + 1)), 5);
}

TEST(IsdAsAddr, IsdAsn)
{
    using namespace scion;

    EXPECT_TRUE(IsdAsn().isUnspecified());
    EXPECT_TRUE(IsdAsn(1).isUnspecified());
    EXPECT_TRUE(IsdAsn(Isd(1), Asn()).isUnspecified());
    EXPECT_FALSE(IsdAsn(Isd(1), Asn(1)).isUnspecified());

    EXPECT_EQ(IsdAsn().isd(), Isd());
    EXPECT_EQ(IsdAsn().asn(), Asn());

    IsdAsn ia{Isd(Isd::MAX_VALUE), Asn(Asn::MAX_VALUE)};
    EXPECT_EQ(ia.isd(), Isd(Isd::MAX_VALUE));
    EXPECT_EQ(ia.asn(), Asn(Asn::MAX_VALUE));

    EXPECT_LT(IsdAsn(0), IsdAsn(IsdAsn::MAX_VALUE));
    std::hash<IsdAsn> h;
    EXPECT_NE(h(IsdAsn(0)), h(IsdAsn(1)));

    EXPECT_EQ(IsdAsn(0x1'ff00'abcd'ffffull), unwrap(IsdAsn::Parse("1-ff00:abcd:ffff")));
    EXPECT_TRUE(hasFailed(IsdAsn::Parse("1024")));
    EXPECT_TRUE(hasFailed(IsdAsn::Parse("ff00:abcd:ffff")));
    EXPECT_TRUE(hasFailed(IsdAsn::Parse("1-ff00:abcd:ffff-")));

    EXPECT_EQ(std::format("{}", IsdAsn()), "0-0");
    EXPECT_EQ(std::format("{}", IsdAsn(0x1'ff00'abcd'ffffull)), "1-ff00:abcd:ffff");
    EXPECT_EQ(std::formatted_size("{}", IsdAsn(0x1'ff00'abcd'ffffull)), 16);
}
