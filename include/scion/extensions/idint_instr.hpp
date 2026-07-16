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

#pragma once

#include "scion/details/flags.hpp"

#include <cstdint>


namespace scion {
namespace idint {

using Nonce = std::array<std::byte, 12>;
using MAC = std::array<std::byte, 4>;

/// \brief Telemetry verifier type
enum class Verifier : std::uint8_t
{
    ThirdParty  = 0,
    Destination = 1,
    Source      = 2,
    MaxValue,
};

/// \brief Aggregation mode
enum class AM : std::uint8_t
{
    Off      = 0,
    AS       = 1,
    Border   = 2,
    Internal = 3,
};

/// \brief Aggregation function
enum class AF : std::uint8_t
{
    First = 0,
    Last  = 1,
    Min   = 2,
    Max   = 3,
    Sum   = 4,
};

/// \brief Instruction bitmap flags
enum class InstrFlag : std::uint8_t
{
    NodeID  = 1 << 3,
    NodeCnt = 1 << 2,
    IgPort  = 1 << 1,
    EgPort  = 1 << 0,
};
using InstrBitmap = scion::details::FlagSet<InstrFlag>;

inline InstrBitmap operator|(InstrFlag lhs, InstrFlag rhs)
{
    return InstrBitmap(lhs) | rhs;
}

/// \brief Instructions
enum class Instr : std::uint8_t
{
    Nop              = 0x00,
    Isd              = 0x01,
    BrLinkType       = 0x02,
    DeviceTypeRole   = 0x03,
    CpuMemUsage      = 0x04,
    CpuTemp          = 0x05,
    AsicTemp         = 0x06,
    FanSpeed         = 0x07,
    TotalPower       = 0x08,
    EnergyMix        = 0x09,
    DeviceVendor     = 0x41,
    DeviceModel      = 0x42,
    SoftwareVersion  = 0x43,
    NodeIpv4Addr     = 0x44,
    IngressPortSpeed = 0x45,
    EgressPortSpeed  = 0x46,
    GpsLat           = 0x47,
    GpsLong          = 0x48,
    Uptime           = 0x49,
    RttNextBr        = 0x4a,
    RttPrevBr        = 0x4b,
    IngressLinkRx    = 0x4c,
    IngressLinkTx    = 0x4d,
    EgressLinkRx     = 0x4e,
    EgressLinkTx     = 0x4f,
    QueueId          = 0x50,
    InstQueueLen     = 0x51,
    AvgQueueLen      = 0x52,
    BufferId         = 0x53,
    InstBufferOcc    = 0x54,
    AvgBufferOcc     = 0x55,
    FwdEnergy        = 0x56,
    Co2Emission      = 0x57,
    Asn              = 0x81,
    IngressTstamp    = 0x82,
    EgressTstamp     = 0x83,
    IgBrIfRxPkts     = 0x84,
    IgBrIfRxBytes    = 0x85,
    IgBrIfRxDropped  = 0x86,
    IgBrIfTxPkts     = 0x87,
    IgBrIfTxBytes    = 0x88,
    IgBrIfTxDropped  = 0x89,
    EgBrIfRxPkts     = 0x8a,
    EgBrIfRxBytes    = 0x8b,
    EgBrIfRxDropped  = 0x8c,
    EgBrIfTxPkts     = 0x8d,
    EgBrIfTxBytes    = 0x8e,
    EgBrIfTxDropped  = 0x8f,
    IgPortRxPkts     = 0x90,
    IgPortRxBytes    = 0x91,
    IgPortRxDropped  = 0x92,
    IgPortTxPkts     = 0x93,
    IgPortTxBytes    = 0x94,
    IgPortTxDropped  = 0x95,
    EgPortRxPkts     = 0x96,
    EgPortRxBytes    = 0x97,
    EgPortRxDropped  = 0x98,
    EgPortTxPkts     = 0x99,
    EgPortTxBytes    = 0x9a,
    EgPortTxDropped  = 0x9b,
    NodeIpv6AddrH    = 0xc1,
    NodeIpv6AddrL    = 0xc2,
};

/// \brief Returns the size of the metadata requested by an instruction.
constexpr std::size_t MetadataSize(Instr instr)
{
    if (instr == Instr::Nop) return 0;
    auto len = (std::uint8_t(instr) >> 6) & 0x03;
    return 2 * (len + 1);
}

} // namespace idint
} // namespace scion
