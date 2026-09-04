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

#include "scion/hdr/scmp.hpp"

namespace scion {
namespace hdr {

std::string_view ScmpDstUnreach::explainCode(Code code)
{
    using namespace std::literals;
    switch (code)
    {
    case NoRoute:
        return "no route to destination"sv;
    case Denied:
        return "communication administratively prohibited"sv;
    case BeyondScope:
        return "beyond scope of source address"sv;
    case AddrUnreach:
        return "address unreachable"sv;
    case PortUnreach:
        return "port unreachable"sv;
    case Policy:
        return "source address failed ingress/egress policy"sv;
    case RejectRoute:
        return "reject route to destination"sv;
    default:
        return "invalid code"sv;
    }
}

std::string_view ScmpParamProblem::explainCode(Code code)
{
    using namespace std::literals;
    switch (code)
    {
    case ErrHdrField:
        return "erroneous header field"sv;
    case UnknownNextHdr:
        return "unknown next header type"sv;
    case InvalComHdr:
        return "invalid common header"sv;
    case UnknownScionVer:
        return "unkown SCION version"sv;
    case FlowIdReq:
        return "flow ID required"sv;
    case InvalidSize:
        return "invalid packet size"sv;
    case UnknownPathType:
        return "unknown path type"sv;
    case UnknownAddress:
        return "unkown address format"sv;
    case InvalAddrHdr:
        return "invalid address header"sv;
    case InvalSrcAddr:
        return "invalid source address"sv;
    case InvalDstAddr:
        return "invalid destination address"sv;
    case NonLocalDelivery:
        return "non-local delivery"sv;
    case InvalidPath:
        return "invalid path"sv;
    case UnknownIgrIf:
        return "unknown hop field cons ingress interface"sv;
    case UnknownEgrIf:
        return "unknown hop field cons egress interface"sv;
    case InvalidHfMac:
        return "invalid hop field MAC"sv;
    case PathExpired:
        return "path expired"sv;
    case InvalSegChange:
        return "invalid segment change"sv;
    case InvalExtHdr:
        return "invalid extension header"sv;
    case UnknownHBHOpt:
        return "unknown hop-by-hop option"sv;
    case UnknownE2ROpt:
        return "unknown end-to-end option"sv;
    default:
        return "invalid code"sv;
    }
}

} // namespace hdr
} // namespace scion
