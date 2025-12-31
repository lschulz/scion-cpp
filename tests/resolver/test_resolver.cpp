#include "scion/resolver.hpp"

#include "gtest/gtest.h"
#include "gmock/gmock.h"
#include "utilities.hpp"

#include <boost/asio.hpp>

#include <filesystem>

extern std::filesystem::path TEST_BASE_PATH;


TEST(Resolver, ResolveHost)
{
    using namespace scion;
    const auto localhost = unwrap(ScIPAddress::Parse("1-ff00:0:0,127.0.0.1"));

    Resolver resolver;
    auto ec = resolver.initialize();
    ASSERT_FALSE(ec) << fmtError(ec);
    resolver.setHostsFile(""); // disable hosts file lookup

    auto addr = resolver.resolveHost("localhost");
    ASSERT_TRUE(isError(addr));
    EXPECT_EQ(addr.error(), ErrorCondition::NameNotFound);

    resolver.setLocalhost(Resolver::AddressSet{localhost});
    addr = resolver.resolveHost("localhost");
    ASSERT_TRUE(addr.has_value()) << fmtError(addr.error());
    EXPECT_THAT(*addr, testing::ElementsAre(localhost));

    addr = resolver.resolveHost("1-ff00:0:0,127.0.0.1");
    ASSERT_TRUE(addr.has_value()) << fmtError(addr.error());
    EXPECT_THAT(*addr, testing::ElementsAre(localhost));

    addr = resolver.resolveHost("example.scion.host");
    ASSERT_TRUE(addr.has_value()) << fmtError(addr.error());
    EXPECT_THAT(*addr, testing::ElementsAre(
        unwrap(ScIPAddress::Parse("1-64512,192.0.2.1")
    )));

    EXPECT_TRUE(hasFailed(resolver.resolveHost("127.0.0.1")));
    EXPECT_TRUE(hasFailed(resolver.resolveHost("1-ff00:0:0,127.0.0..1")));
    EXPECT_TRUE(hasFailed(resolver.resolveHost("google.com")));
}

TEST(Resolver, ResolveHostAsync)
{
    using namespace scion;
    const auto localhost = unwrap(ScIPAddress::Parse("1-ff00:0:0,127.0.0.1"));

    boost::asio::io_context ioCtx;
    Resolver resolver;
    auto ec = resolver.initialize();
    ASSERT_FALSE(ec) << fmtError(ec);
    resolver.setHostsFile(""); // disable hosts file lookup

    resolver.resolveHostAsync("localhost", ioCtx, [] (auto addr) {
        ASSERT_TRUE(isError(addr));
        EXPECT_EQ(addr.error(), ErrorCondition::NameNotFound);
    });

    resolver.setLocalhost(Resolver::AddressSet{localhost});
    resolver.resolveHostAsync("localhost", ioCtx, [&] (auto addr) {
        ASSERT_TRUE(addr.has_value()) << fmtError(addr.error());
        EXPECT_THAT(*addr, testing::ElementsAre(localhost));
    });

    resolver.resolveHostAsync("1-ff00:0:0,127.0.0.1", ioCtx, [&] (auto addr) {
        ASSERT_TRUE(addr.has_value()) << fmtError(addr.error());
        EXPECT_THAT(*addr, testing::ElementsAre(localhost));
    });

    resolver.resolveHostAsync("example.scion.host", ioCtx, [] (auto addr) {
        ASSERT_TRUE(addr.has_value()) << fmtError(addr.error());
        EXPECT_THAT(*addr, testing::ElementsAre(
            unwrap(ScIPAddress::Parse("1-64512,192.0.2.1")
        )));
    });

    ioCtx.run();
}

TEST(Resolver, ResolveService)
{
    using namespace scion;
    const auto localhost = Resolver::AddressSet{
        unwrap(ScIPAddress::Parse("1-ff00:0:0,127.0.0.1")),
        unwrap(ScIPAddress::Parse("1-ff00:0:0,::1")),
    };

    Resolver resolver;
    auto ec = resolver.initialize();
    ASSERT_FALSE(ec) << fmtError(ec);
    resolver.setLocalhost(localhost);
    resolver.setHostsFile(""); // disable hosts file lookup

    auto addr = resolver.resolveService("localhost");
    ASSERT_TRUE(addr.has_value()) << fmtError(addr.error());
    EXPECT_THAT(*addr, testing::ElementsAre(
        ScIPEndpoint(localhost[0], 0),
        ScIPEndpoint(localhost[1], 0)
    ));

    addr = resolver.resolveService("localhost:80");
    ASSERT_TRUE(addr.has_value()) << fmtError(addr.error());
    EXPECT_THAT(*addr, testing::ElementsAre(
        ScIPEndpoint(localhost[0], 80),
        ScIPEndpoint(localhost[1], 80)
    ));

    addr = resolver.resolveService("1-ff00:0:0,127.0.0.1");
    ASSERT_TRUE(addr.has_value()) << fmtError(addr.error());
    EXPECT_THAT(*addr, testing::ElementsAre(ScIPEndpoint(localhost[0], 0)));

    addr = resolver.resolveService("1-ff00:0:0,::1");
    ASSERT_TRUE(addr.has_value()) << fmtError(addr.error());
    EXPECT_THAT(*addr, testing::ElementsAre(ScIPEndpoint(localhost[1], 0)));

    addr = resolver.resolveService("1-ff00:0:0,127.0.0.1:80");
    ASSERT_TRUE(addr.has_value()) << fmtError(addr.error());
    EXPECT_THAT(*addr, testing::ElementsAre(ScIPEndpoint(localhost[0], 80)));

    addr = resolver.resolveService("[1-ff00:0:0,::1]:80");
    ASSERT_TRUE(addr.has_value()) << fmtError(addr.error());
    EXPECT_THAT(*addr, testing::ElementsAre(ScIPEndpoint(localhost[1], 80)));
}

TEST(Resolver, HostsFile)
{
    using namespace scion;
    std::filesystem::path hostsFile = TEST_BASE_PATH / "resolver/data/hosts";

    auto res = queryHostsFile("example.com", hostsFile.c_str());
    ASSERT_TRUE(res.has_value()) << fmtError(res.error());
    ASSERT_THAT(*res, testing::ElementsAre(
        unwrap(ScIPAddress::Parse("1-ff00:0:0,127.0.0.1")),
        unwrap(ScIPAddress::Parse("1-ff00:0:0,::1"))
    ));

    res = queryHostsFile("example.de", hostsFile.c_str());
    ASSERT_TRUE(isError(res));
    ASSERT_EQ(res.error(), ErrorCondition::NameNotFound);
}
