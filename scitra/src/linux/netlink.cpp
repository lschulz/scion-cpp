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

#include "scitra/linux/error_codes.hpp"
#include "scitra/linux/netlink.hpp"

#include "scion/posix/sockaddr.hpp"

#include <linux/rtnetlink.h>
#include <memory>

using namespace scion::generic;
using std::uint32_t;
using std::size_t;


NetlinkRoute::NetlinkRoute()
    : seq(time(NULL))
{}

std::error_code NetlinkRoute::open()
{
    nl = mnl_socket_open(NETLINK_ROUTE);
    if (!nl) return ScitraError::SocketClosed;
    if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0) {
        mnl_socket_close(nl);
        return std::error_code(errno, std::generic_category());
    }
    return ScitraError::Ok;
}

void NetlinkRoute::close()
{
    if (nl) mnl_socket_close(nl);
}

std::error_code NetlinkRoute::setInterfaceState(const std::string& dev, bool up)
{
    if (!nl) return ScitraError::SocketClosed;
    size_t bufsize = MNL_SOCKET_BUFFER_SIZE;
    auto buf = std::make_unique<char[]>(bufsize);

    auto nlh = mnl_nlmsg_put_header(buf.get());
    nlh->nlmsg_type = RTM_SETLINK;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    nlh->nlmsg_seq = seq++;

    auto info = (ifinfomsg*)mnl_nlmsg_put_extra_header(nlh, sizeof(ifinfomsg));
    info->ifi_flags = up ? IFF_UP : 0;
    info->ifi_change = 0xffffffff; // reserved for future use (see man rtnetlink)
    if (!mnl_attr_put_strz_check(nlh, bufsize, IFLA_IFNAME, dev.c_str()))
        return ScitraError::LogicError;

    return execute(nlh, buf.get(), bufsize);
}

Maybe<uint32_t> NetlinkRoute::getInterfaceMTU(const std::string& dev)
{
    if (!nl) return Error(ScitraError::SocketClosed);
    size_t bufsize = MNL_SOCKET_BUFFER_SIZE;
    auto buf = std::make_unique<char[]>(bufsize);

    auto nlh = mnl_nlmsg_put_header(buf.get());
    nlh->nlmsg_type = RTM_GETLINK;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    nlh->nlmsg_seq = seq++;

    auto info = (ifinfomsg*)mnl_nlmsg_put_extra_header(nlh, sizeof(ifinfomsg));
    info->ifi_change = 0xffffffff; // reserved for future use (see man rtnetlink)
    if (!mnl_attr_put_strz_check(nlh, bufsize, IFLA_IFNAME, dev.c_str()))
        return Error(ScitraError::LogicError);

    if (auto ec = execute(nlh, buf.get(), bufsize); ec) {
        return Error(ec);
    }

    // Parse response
    if (mnl_nlmsg_ok(nlh, bufsize) && nlh->nlmsg_type == RTM_NEWLINK) {
        if (mnl_nlmsg_get_payload_len(nlh) > sizeof(ifinfomsg)) {
            // see mnl_attr_for_each
            auto attr = (nlattr*)mnl_nlmsg_get_payload_offset(nlh, sizeof(ifinfomsg));
            while (mnl_attr_ok(attr, (char*)mnl_nlmsg_get_payload_tail(nlh) - (char*)attr)) {
                if (attr->nla_type == IFLA_MTU) {
                    return mnl_attr_get_u32(attr);
                }
                attr = mnl_attr_next(attr);
            }
        }
    }
    return Error(ScitraError::LogicError);
}

std::error_code NetlinkRoute::setInterfaceMTU(const std::string& dev, uint32_t mtu)
{
    if (!nl) return ScitraError::SocketClosed;
    size_t bufsize = MNL_SOCKET_BUFFER_SIZE;
    auto buf = std::make_unique<char[]>(bufsize);

    auto nlh = mnl_nlmsg_put_header(buf.get());
    nlh->nlmsg_type = RTM_SETLINK;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    nlh->nlmsg_seq = seq++;

    auto info = (ifinfomsg*)mnl_nlmsg_put_extra_header(nlh, sizeof(ifinfomsg));
    info->ifi_change = 0xffffffff; // reserved for future use (see man rtnetlink)
    if (!mnl_attr_put_strz_check(nlh, bufsize, IFLA_IFNAME, dev.c_str()))
        return ScitraError::LogicError;
    if (!mnl_attr_put_u32_check(nlh, bufsize, IFLA_MTU, mtu))
        return ScitraError::LogicError;

    return execute(nlh, buf.get(), bufsize);
}

std::error_code NetlinkRoute::addRoute(
    const IPAddress& dst, PrefixLen prefixlen, const std::string& dev, int metric)
{
    if (!nl) return ScitraError::SocketClosed;
    int iface = if_nametoindex(dev.c_str());
    if (iface == 0) return ScitraError::InterfaceNotFound;

    size_t bufsize = MNL_SOCKET_BUFFER_SIZE;
    auto buf = std::make_unique<char[]>(bufsize);

    auto nlh = mnl_nlmsg_put_header(buf.get());
    nlh->nlmsg_type = RTM_NEWROUTE;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_ACK;
    nlh->nlmsg_seq = seq++;

    auto rtm = (rtmsg*)mnl_nlmsg_put_extra_header(nlh, sizeof(rtmsg));
    rtm->rtm_dst_len = prefixlen;
    rtm->rtm_protocol = RTPROT_STATIC;
    rtm->rtm_table = RT_TABLE_MAIN;
    rtm->rtm_type = RTN_UNICAST;
    rtm->rtm_scope = RT_SCOPE_UNIVERSE;
    if (!mnl_attr_put_u32_check(nlh, bufsize, RTA_OIF, iface))
        return ScitraError::LogicError;
    if (!mnl_attr_put_u32_check(nlh, bufsize, RTA_PRIORITY, metric))
        return ScitraError::LogicError;
    if (dst.is4()) {
        rtm->rtm_family = AF_INET;
        uint32_t ip = dst.getIPv4();
        if (!mnl_attr_put_u32_check(nlh, bufsize, RTA_DST, ip))
            return ScitraError::LogicError;
    } else {
        rtm->rtm_family = AF_INET6;
        auto ip = scion::generic::toUnderlay<in6_addr>(dst);
        if (scion::isError(ip)) return ScitraError::LogicError;
        if (!mnl_attr_put_check(nlh, bufsize, RTA_DST, sizeof(in6_addr), &(*ip)))
            return ScitraError::LogicError;
    }

    return execute(nlh, buf.get(), bufsize);
}

std::error_code NetlinkRoute::delRoute(
    const IPAddress& dst, PrefixLen prefixlen, const std::string& dev)
{
    using namespace std::literals;

    if (!nl) return ScitraError::SocketClosed;
    int iface = if_nametoindex(dev.c_str());
    if (iface == 0) return ScitraError::InterfaceNotFound;

    size_t bufsize = MNL_SOCKET_BUFFER_SIZE;
    auto buf = std::make_unique<char[]>(bufsize);

    auto nlh = mnl_nlmsg_put_header(buf.get());
    nlh->nlmsg_type = RTM_DELROUTE;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    nlh->nlmsg_seq = seq++;

    auto rtm = (rtmsg*)mnl_nlmsg_put_extra_header(nlh, sizeof(rtmsg));
    rtm->rtm_dst_len = prefixlen;
    rtm->rtm_table = RT_TABLE_MAIN;
    if (!mnl_attr_put_u32_check(nlh, bufsize, RTA_OIF, iface))
        return ScitraError::LogicError;
    if (dst.is4()) {
        rtm->rtm_family = AF_INET;
        uint32_t ip = dst.getIPv4();
        if (!mnl_attr_put_u32_check(nlh, bufsize, RTA_DST, ip))
            return ScitraError::LogicError;
    } else {
        rtm->rtm_family = AF_INET6;
        auto ip = scion::generic::toUnderlay<in6_addr>(dst);
        if (scion::isError(ip)) return ScitraError::LogicError;
        if (!mnl_attr_put_check(nlh, bufsize, RTA_DST, sizeof(in6_addr), &(*ip)))
            return ScitraError::LogicError;
    }

    return execute(nlh, buf.get(), bufsize);
}

std::error_code NetlinkRoute::modAddress(
    const IPAddress& addr, PrefixLen prefixlen, const std::string& dev, bool del)
{
    if (!nl) return ScitraError::SocketClosed;
    int iface = if_nametoindex(dev.c_str());
    if (iface == 0) return ScitraError::InterfaceNotFound;

    size_t bufsize = MNL_SOCKET_BUFFER_SIZE;
    auto buf = std::make_unique<char[]>(bufsize);

    auto nlh = mnl_nlmsg_put_header(buf.get());
    nlh->nlmsg_type = del ? RTM_DELADDR : RTM_NEWADDR;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    nlh->nlmsg_seq = seq++;

    auto msg = (ifaddrmsg*)mnl_nlmsg_put_extra_header(nlh, sizeof(struct ifaddrmsg));
    msg->ifa_prefixlen = prefixlen;
    if (addr.is4()) {
        msg->ifa_family = AF_INET;
        uint32_t ip = addr.getIPv4();
        if (!mnl_attr_put_u32_check(nlh, bufsize, IFA_ADDRESS, ip))
            return ScitraError::LogicError;
    } else {
        msg->ifa_family = AF_INET6;
            if (addr.hasZone())
        msg->ifa_scope = addr.zoneId();
        auto ip = scion::generic::toUnderlay<in6_addr>(addr);
        if (!mnl_attr_put_check(nlh, bufsize, IFA_ADDRESS, sizeof(struct in6_addr), &(*ip)))
            return ScitraError::LogicError;
    }
    msg->ifa_index = iface;

    return execute(nlh, buf.get(), bufsize);
}

std::error_code NetlinkRoute::execute(nlmsghdr* nlh, char* buf, size_t bufsize)
{
    auto portid = mnl_socket_get_portid(nl);
    if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
        return std::error_code(errno, std::generic_category());
    }
    ssize_t numbytes = mnl_socket_recvfrom(nl, buf, bufsize);
    if (numbytes < 0) {
        return std::error_code(errno, std::generic_category());
    }
    if (mnl_cb_run(buf, numbytes, nlh->nlmsg_seq, portid, nullptr, nullptr) < 0) {
        return std::error_code(errno, std::generic_category());
    }
    return ScitraError::Ok;
}
