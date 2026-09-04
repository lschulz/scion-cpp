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

#include "tables.hpp"

using namespace std::literals;
using namespace scion::idint;


using Mode = std::pair<scion::idint::AM, std::string_view>;
extern const std::array<Mode, 4> IdIntAgrModeTable = {
    Mode{AM::Off,      "off"sv},
    Mode{AM::AS,       "AS"sv},
    Mode{AM::Border,   "border"sv},
    Mode{AM::Internal, "internal"sv},
};

using Func = std::pair<scion::idint::AF, std::string_view>;
extern const std::array<Func, 5> IdIntAgrFuncTable = {
    Func{AF::First, "first"sv},
    Func{AF::Last,  "last"sv},
    Func{AF::Min,    "min"sv},
    Func{AF::Max,    "max"sv},
    Func{AF::Sum,    "sum"sv},
};

const std::array<InstrDef, 79> IdIntInstrTable = {
    InstrDef{Instr::Nop,                 4, "NOP"sv},
    InstrDef{Instr::Isd,                 6, "ISD"sv},
    InstrDef{Instr::BrLinkType,         14, "BR_LINK_TYPE"sv},
    InstrDef{Instr::DeviceTypeRole,     20, "DEVICE_TYPE_ROLE"sv},
    InstrDef{Instr::CpuUserNow,         13, "CPU_USER_NOW"sv},
    InstrDef{Instr::CpuUser1Min,        13, "CPU_USER_1MIN"sv},
    InstrDef{Instr::CpuUser5Min,        13, "CPU_USER_5MIN"sv},
    InstrDef{Instr::CpuSysNow,          13, "CPU_SYS_NOW"sv},
    InstrDef{Instr::CpuSys1Min,         13, "CPU_SYS_1MIN"sv},
    InstrDef{Instr::CpuSys5Min,         13, "CPU_SYS_5MIN"sv},
    InstrDef{Instr::CpuRunnableNow,     19, "CPU_RUNNABLE_NOW"sv},
    InstrDef{Instr::CpuRunnable1Min,    19, "CPU_RUNNABLE_1MIN"sv},
    InstrDef{Instr::CpuRunnable5Min,    19, "CPU_RUNNABLE_5MIN"sv},
    InstrDef{Instr::HostCpuNow,         14, "HOST_CPU_NOW"sv},
    InstrDef{Instr::HostCpu1Min,        14, "HOST_CPU_1MIN"sv},
    InstrDef{Instr::HostCpu5Min,        14, "HOST_CPU_5MIN"sv},
    InstrDef{Instr::HostCpuUserNow,     18, "HOST_CPU_USER_NOW"sv},
    InstrDef{Instr::HostCpuUser1Min,    18, "HOST_CPU_USER_1MIN"sv},
    InstrDef{Instr::HostCpuUser5Min,    18, "HOST_CPU_USER_5MIN"sv},
    InstrDef{Instr::HostCpuSysNow,      18, "HOST_CPU_SYS_NOW"sv},
    InstrDef{Instr::HostCpuSys1Min,     18, "HOST_CPU_SYS_1MIN"sv},
    InstrDef{Instr::HostCpuSys5Min,     18, "HOST_CPU_SYS_5MIN"sv},
    InstrDef{Instr::HostCpuSoftIrqNow,  23, "HOST_CPU_SOFT_IRQ_NOW"sv},
    InstrDef{Instr::HostCpuSoftIrq1Min, 23, "HOST_CPU_SOFT_IRQ_1MIN"sv},
    InstrDef{Instr::HostCpuSoftIrq5Min, 23, "HOST_CPU_SOFT_IRQ_5MIN"sv},
    InstrDef{Instr::TotalPower,         12, "TOTAL_POWER"sv},
    InstrDef{Instr::EnergyMix,          12, "ENERGY_MIX"sv},
    InstrDef{Instr::DeviceVendor,       14, "DEVICE_VENDOR"sv},
    InstrDef{Instr::DeviceModel,        14, "DEVICE_MODEL"sv},
    InstrDef{Instr::SoftwareVersion,    17, "SOFTWARE_VERSION"sv},
    InstrDef{Instr::NodeIpv4Addr,       15, "NODE_IPV4_ADDR"sv},
    InstrDef{Instr::IngressPortSpeed,   19, "INGRESS_PORT_SPEED"sv},
    InstrDef{Instr::EgressPortSpeed,    19, "EGRESS_PORT_SPEED"sv},
    InstrDef{Instr::GpsLat,             10, "GPS_LAT"sv},
    InstrDef{Instr::GpsLong,            10, "GPS_LONG"sv},
    InstrDef{Instr::Uptime,             10, "UPTIME"sv},
    InstrDef{Instr::RttNextBr,          12, "RTT_NEXT_BR"sv},
    InstrDef{Instr::RttPrevBr,          12, "RTT_PREV_BR"sv},
    InstrDef{Instr::IngressLinkRx,      16, "INGRESS_LINK_RX"sv},
    InstrDef{Instr::IngressLinkTx,      16, "INGRESS_LINK_TX"sv},
    InstrDef{Instr::EgressLinkRx,       16, "EGRESS_LINK_RX"sv},
    InstrDef{Instr::EgressLinkTx,       16, "EGRESS_LINK_TX"sv},
    InstrDef{Instr::QueueId,             9, "QUEUE_ID"sv},
    InstrDef{Instr::InstQueueLen,       16, "INST_QUEUE_LEN"sv},
    InstrDef{Instr::AvgQueueLen,        16, "AVG_QUEUE_LEN"sv},
    InstrDef{Instr::BufferId,            9, "BUFFER_ID"sv},
    InstrDef{Instr::InstBufferOcc,      16, "INST_BUFFER_OCC"sv},
    InstrDef{Instr::AvgBufferOcc,       16, "AVG_BUFFER_OCC"sv},
    InstrDef{Instr::FwdEnergy,          13, "FWD_ENERGY"sv},
    InstrDef{Instr::Co2Emission,        13, "CO2_EMISSION"sv},
    InstrDef{Instr::Asn,                16, "ASN"sv},
    InstrDef{Instr::IngressTstamp,      15, "INGRESS_TSTAMP"sv},
    InstrDef{Instr::EgressTstamp,       15, "EGRESS_TSTAMP"sv},
    InstrDef{Instr::IgBrIfRxPkts,       20, "IG_BR_IF_RX_PKTS"sv},
    InstrDef{Instr::IgBrIfRxBytes,      20, "IG_BR_IF_RX_BYTES"sv},
    InstrDef{Instr::IgBrIfRxDropped,    20, "IG_BR_IF_RX_DROPPED"sv},
    InstrDef{Instr::IgBrIfTxPkts,       20, "IG_BR_IF_TX_PKTS"sv},
    InstrDef{Instr::IgBrIfTxBytes,      20, "IG_BR_IF_TX_BYTES"sv},
    InstrDef{Instr::IgBrIfTxDropped,    20, "IG_BR_IF_TX_DROPPED"sv},
    InstrDef{Instr::EgBrIfRxPkts,       20, "EG_BR_IF_RX_PKTS"sv},
    InstrDef{Instr::EgBrIfRxBytes,      20, "EG_BR_IF_RX_BYTES"sv},
    InstrDef{Instr::EgBrIfRxDropped,    20, "EG_BR_IF_RX_DROPPED"sv},
    InstrDef{Instr::EgBrIfTxPkts,       20, "EG_BR_IF_TX_PKTS"sv},
    InstrDef{Instr::EgBrIfTxBytes,      20, "EG_BR_IF_TX_BYTES"sv},
    InstrDef{Instr::EgBrIfTxDropped,    20, "EG_BR_IF_TX_DROPPED"sv},
    InstrDef{Instr::IgPortRxPkts,       20, "IG_PORT_RX_PKTS"sv},
    InstrDef{Instr::IgPortRxBytes,      20, "IG_PORT_RX_BYTES"sv},
    InstrDef{Instr::IgPortRxDropped,    20, "IG_PORT_RX_DROPPED"sv},
    InstrDef{Instr::IgPortTxPkts,       20, "IG_PORT_TX_PKTS"sv},
    InstrDef{Instr::IgPortTxBytes,      20, "IG_PORT_TX_BYTES"sv},
    InstrDef{Instr::IgPortTxDropped,    20, "IG_PORT_TX_DROPPED"sv},
    InstrDef{Instr::EgPortRxPkts,       20, "EG_PORT_RX_PKTS"sv},
    InstrDef{Instr::EgPortRxBytes,      20, "EG_PORT_RX_BYTES"sv},
    InstrDef{Instr::EgPortRxDropped,    20, "EG_PORT_RX_DROPPED"sv},
    InstrDef{Instr::EgPortTxPkts,       20, "EG_PORT_TX_PKTS"sv},
    InstrDef{Instr::EgPortTxBytes,      20, "EG_PORT_TX_BYTES"sv},
    InstrDef{Instr::EgPortTxDropped,    20, "EG_PORT_TX_DROPPED"sv},
    InstrDef{Instr::NodeIpv6AddrH,      17, "NODE_IPV6_ADDR_H"sv},
    InstrDef{Instr::NodeIpv6AddrL,      17, "NODE_IPV6_ADDR_L"sv},
};
