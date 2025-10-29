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

#include "scion/daemon/client.hpp"
#include "scion/path/path_meta.hpp"
#include "scion/path/path.hpp"
#include "scion/path/policy.hpp"

#include "gtest/gtest.h"
#include "gmock/gmock.h"
#include "utilities.hpp"

extern std::filesystem::path TEST_BASE_PATH;


TEST(PathPolicy, TrafficMatcherMatch)
{
    using namespace scion;
    using namespace scion::path_policy;

    TrafficMatcher m(
        ScIPEndpoint(),
        unwrap(ScIPEndpoint::Parse("[1-64513,::1]:443")),
        hdr::ScionProto::TCP,
        0
    );

    EXPECT_TRUE(m.match(
        unwrap(ScIPEndpoint::Parse("[1-64512,::1]:52000")),
        unwrap(ScIPEndpoint::Parse("[1-64513,::1]:443")),
        hdr::ScionProto::TCP,
        1
    ));
    EXPECT_FALSE(m.match(
        unwrap(ScIPEndpoint::Parse("[1-64512,::1]:52000")),
        unwrap(ScIPEndpoint::Parse("[1-64513,::1]:443")),
        hdr::ScionProto::UDP,
        0
    ));
}

TEST(PathPolicy, HopPredicateParse)
{
    using namespace scion;
    using namespace scion::path_policy;

    auto hp = HopPredicate::Parse("0");
    ASSERT_TRUE(hp.has_value());
    EXPECT_TRUE(hp->match(IsdAsn(Isd(1), Asn(1)), 1, 1));

    hp = HopPredicate::Parse("1");
    ASSERT_TRUE(hp.has_value());
    EXPECT_TRUE(hp->match(IsdAsn(Isd(1), Asn(1)), 1, 1));
    EXPECT_FALSE(hp->match(IsdAsn(Isd(2), Asn(1)), 1, 1));

    hp = HopPredicate::Parse("1-1");
    ASSERT_TRUE(hp.has_value());
    EXPECT_TRUE(hp->match(IsdAsn(Isd(1), Asn(1)), 1, 1));
    EXPECT_FALSE(hp->match(IsdAsn(Isd(1), Asn(2)), 1, 1));

    hp = HopPredicate::Parse("1-ff00:0:1");
    ASSERT_TRUE(hp.has_value());
    EXPECT_TRUE(hp->match(IsdAsn(Isd(1), Asn(0xff00'0000'0001ull)), 1, 1));
    EXPECT_FALSE(hp->match(IsdAsn(Isd(1), Asn(2)), 1, 1));

    hp = HopPredicate::Parse("1-ff00:0:1#1");
    ASSERT_TRUE(hp.has_value());
    EXPECT_TRUE(hp->match(IsdAsn(Isd(1), Asn(0xff00'0000'0001ull)), 1, 2));
    EXPECT_TRUE(hp->match(IsdAsn(Isd(1), Asn(0xff00'0000'0001ull)), 2, 1));
    EXPECT_FALSE(hp->match(IsdAsn(Isd(1), Asn(0xff00'0000'0001ull)), 2, 2));

    hp = HopPredicate::Parse("1-ff00:0:1#1,2");
    ASSERT_TRUE(hp.has_value());
    EXPECT_TRUE(hp->match(IsdAsn(Isd(1), Asn(0xff00'0000'0001ull)), 1, 2));
    EXPECT_FALSE(hp->match(IsdAsn(Isd(1), Asn(0xff00'0000'0001ull)), 1, 3));
    EXPECT_FALSE(hp->match(IsdAsn(Isd(1), Asn(0xff00'0000'0001ull)), 3, 2));
}

TEST(PathPolicy, HopPredicateSequence)
{
    namespace pm = scion::path_meta;
    using namespace scion;
    using namespace scion::path_policy;
    using namespace scion::path_policy::details;

    static const pm::Interfaces meta(std::vector<pm::Hop>{
        pm::Hop{
            .isdAsn = IsdAsn(0x1ff0000000111),
            .ingress = 0,
            .egress = 2,
        },
        pm::Hop{
            .isdAsn = IsdAsn(0x2ff0000000211),
            .ingress = 5,
            .egress = 4,
        },
        pm::Hop{
            .isdAsn = IsdAsn(0x2ff0000000222),
            .ingress = 3,
            .egress = 0,
        },
    });

    auto seq = interfacesToSeqExpr(meta);
    ASSERT_EQ(seq, "1-ff00:0:111#0,2 2-ff00:0:211#5,4 2-ff00:0:222#3,0");

    auto re = translateHopSeqExprToRegex("0*");
    ASSERT_TRUE(re.has_value());
    EXPECT_TRUE(std::regex_match(seq, *re));

    re = translateHopSeqExprToRegex("1 0+ 2");
    ASSERT_TRUE(re.has_value());
    EXPECT_TRUE(std::regex_match(seq, *re));

    re = translateHopSeqExprToRegex("1 0* 1");
    ASSERT_TRUE(re.has_value());
    EXPECT_FALSE(std::regex_match(seq, *re));

    re = translateHopSeqExprToRegex("0* 2-ff00:0:211 0*");
    ASSERT_TRUE(re.has_value());
    EXPECT_TRUE(std::regex_match(seq, *re));

    re = translateHopSeqExprToRegex("0* 2-ff00:0:211#5,4 0*");
    ASSERT_TRUE(re.has_value());
    EXPECT_TRUE(std::regex_match(seq, *re));

    re = translateHopSeqExprToRegex("0* 2-ff00:0:211#5,6 0*");
    ASSERT_TRUE(re.has_value());
    EXPECT_FALSE(std::regex_match(seq, *re));

    // extra spaces around hop predicates
    re = translateHopSeqExprToRegex(" 1-ff00:0:111#2  0*  2-ff00:0:222#3 ");
    ASSERT_TRUE(re.has_value());
    EXPECT_TRUE(std::regex_match(seq, *re));

    re = translateHopSeqExprToRegex("1-ff00:0:111#2 0 (2-ff00:0:222#1 | 2-ff00:0:222#3)");
    ASSERT_TRUE(re.has_value());
    EXPECT_TRUE(std::regex_match(seq, *re));

    re = translateHopSeqExprToRegex("1-ff00:0:111#2 0+ 2-ff00:0:222#1");
    ASSERT_TRUE(re.has_value());
    EXPECT_FALSE(std::regex_match(seq, *re));
}

TEST(PathPolicy, PolicySet)
{
    namespace pm = scion::path_meta;
    using namespace scion;
    using namespace scion::path_policy;
    using namespace std::chrono_literals;

    PolicySet policies;
    auto [ec, msg] = policies.loadJsonFile(TEST_BASE_PATH / "path/data/policy.json");
    ASSERT_FALSE(ec) << msg;

    auto src = unwrap(IsdAsn::Parse("1-64512"));
    auto dst = unwrap(IsdAsn::Parse("1-ff00:0:1"));
    std::vector<PathPtr> paths;
    for (auto&& buf : loadPackets("path/data/paths.bin")) {
        proto::daemon::v1::Path pb;
        pb.ParseFromArray(buf.data(), (int)(buf.size()));
        auto flags = daemon::PathReqFlags::AllMetadata;
        auto res = daemon::details::pathFromProtobuf(src, dst, pb, flags);
        ASSERT_TRUE(res.has_value()) << getError(res);
        paths.push_back(std::move(*res));
    }

    auto& policy = policies.getPolicy(
        unwrap(ScIPEndpoint::Parse("1-64512,127.0.0.1:34000")),
        unwrap(ScIPEndpoint::Parse("[1-ff00:0:1,10.0.0.1]:22")),
        hdr::ScionProto::TCP,
        0
    );
    EXPECT_FALSE(policy.test(*paths.at(0)));
    EXPECT_FALSE(policy.test(*paths.at(1)));
    EXPECT_TRUE(policy.test(*paths.at(2)));

    std::vector copy = paths;
    auto filtered = policies.apply(
        unwrap(ScIPEndpoint::Parse("1-64512,127.0.0.1:34000")),
        unwrap(ScIPEndpoint::Parse("[1-ff00:0:1,10.0.0.1]:22")),
        hdr::ScionProto::UDP,
        1,
        copy
    );
    ASSERT_EQ(filtered.data(), copy.data());
    EXPECT_THAT(filtered, testing::ElementsAre(
        paths.at(2), paths.at(1)
    ));
}
