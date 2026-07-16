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

using namespace scion::idint;


using Mode = std::pair<std::string_view, scion::idint::AM>;
extern const std::array<Mode, 4> IdIntAgrModeTable = {
    Mode{"fff", AM::Off},
    Mode{"AS", AM::AS},
    Mode{"border", AM::Border},
    Mode{"internal", AM::Internal},
};

using Func = std::pair<std::string_view, scion::idint::AF>;
extern const std::array<Func, 5> IdIntAgrFuncTable = {
    Func{"first", AF::First},
    Func{"last", AF::Last},
    Func{"min", AF::Min},
    Func{"max", AF::Max},
    Func{"sum", AF::Sum},
};

using Instruction = std::pair<std::string_view, scion::idint::Instr>;
const std::array<Instruction, 256> IdIntInstructionTable = {
    Instruction{"NOP", Instr::Nop},
    Instruction{"ISD", Instr::Isd},
    Instruction{"BR_LINK_TYPE", Instr::BrLinkType},
    Instruction{"DEVICE_TYPE_ROLE", Instr::DeviceTypeRole},
    Instruction{"CPU_MEM_USAGE", Instr::CpuMemUsage},
    Instruction{"CPU_TEMP", Instr::CpuTemp},
    Instruction{"ASIC_TEMP", Instr::AsicTemp},
    Instruction{"FAN_SPEED", Instr::FanSpeed},
    Instruction{"TOTAL_POWER", Instr::TotalPower},
    Instruction{"ENERGY_MIX", Instr::EnergyMix},
    Instruction{"DEVICE_VENDOR", Instr::DeviceVendor},
    Instruction{"DEVICE_MODEL", Instr::DeviceModel},
    Instruction{"SOFTWARE_VERSION", Instr::SoftwareVersion},
    Instruction{"NODE_IPV4_ADDR", Instr::NodeIpv4Addr},
    Instruction{"INGRESS_PORT_SPEED", Instr::IngressPortSpeed},
    Instruction{"EGRESS_PORT_SPEED", Instr::EgressPortSpeed},
    Instruction{"GPS_LAT", Instr::GpsLat},
    Instruction{"GPS_LONG", Instr::GpsLong},
    Instruction{"UPTIME", Instr::Uptime},
    Instruction{"RTT_NEXT_BR", Instr::RttNextBr},
    Instruction{"RTT_PREV_BR", Instr::RttPrevBr},
    Instruction{"INGRESS_LINK_RX", Instr::IngressLinkRx},
    Instruction{"INGRESS_LINK_TX", Instr::IngressLinkTx},
    Instruction{"EGRESS_LINK_RX", Instr::EgressLinkRx},
    Instruction{"EGRESS_LINK_TX", Instr::EgressLinkTx},
    Instruction{"QUEUE_ID", Instr::QueueId},
    Instruction{"INST_QUEUE_LEN", Instr::InstQueueLen},
    Instruction{"AVG_QUEUE_LEN", Instr::AvgQueueLen},
    Instruction{"BUFFER_ID", Instr::BufferId},
    Instruction{"INST_BUFFER_OCC", Instr::InstBufferOcc},
    Instruction{"AVG_BUFFER_OCC", Instr::AvgBufferOcc},
    Instruction{"FWD_ENERGY", Instr::FwdEnergy},
    Instruction{"CO2_EMISSION", Instr::Co2Emission},
    Instruction{"ASN", Instr::Asn},
    Instruction{"INGRESS_TSTAMP", Instr::IngressTstamp},
    Instruction{"EGRESS_TSTAMP", Instr::EgressTstamp},
    Instruction{"IG_BR_IF_RX_PKTS", Instr::IgBrIfRxPkts},
    Instruction{"IG_BR_IF_RX_BYTES", Instr::IgBrIfRxBytes},
    Instruction{"IG_BR_IF_RX_DROPPED", Instr::IgBrIfRxDropped},
    Instruction{"IG_BR_IF_TX_PKTS", Instr::IgBrIfTxPkts},
    Instruction{"IG_BR_IF_TX_BYTES", Instr::IgBrIfTxBytes},
    Instruction{"IG_BR_IF_TX_DROPPED", Instr::IgBrIfTxDropped},
    Instruction{"EG_BR_IF_RX_PKTS", Instr::EgBrIfRxPkts},
    Instruction{"EG_BR_IF_RX_BYTES", Instr::EgBrIfRxBytes},
    Instruction{"EG_BR_IF_RX_DROPPED", Instr::EgBrIfRxDropped},
    Instruction{"EG_BR_IF_TX_PKTS", Instr::EgBrIfTxPkts},
    Instruction{"EG_BR_IF_TX_BYTES", Instr::EgBrIfTxBytes},
    Instruction{"EG_BR_IF_TX_DROPPED", Instr::EgBrIfTxDropped},
    Instruction{"IG_PORT_RX_PKTS", Instr::IgPortRxPkts},
    Instruction{"IG_PORT_RX_BYTES", Instr::IgPortRxBytes},
    Instruction{"IG_PORT_RX_DROPPED", Instr::IgPortRxDropped},
    Instruction{"IG_PORT_TX_PKTS", Instr::IgPortTxPkts},
    Instruction{"IG_PORT_TX_BYTES", Instr::IgPortTxBytes},
    Instruction{"IG_PORT_TX_DROPPED", Instr::IgPortTxDropped},
    Instruction{"EG_PORT_RX_PKTS", Instr::EgPortRxPkts},
    Instruction{"EG_PORT_RX_BYTES", Instr::EgPortRxBytes},
    Instruction{"EG_PORT_RX_DROPPED", Instr::EgPortRxDropped},
    Instruction{"EG_PORT_TX_PKTS", Instr::EgPortTxPkts},
    Instruction{"EG_PORT_TX_BYTES", Instr::EgPortTxBytes},
    Instruction{"EG_PORT_TX_DROPPED", Instr::EgPortTxDropped},
    Instruction{"NODE_IPV6_ADDR_H", Instr::NodeIpv6AddrH},
    Instruction{"NODE_IPV6_ADDR_L", Instr::NodeIpv6AddrL},
};
