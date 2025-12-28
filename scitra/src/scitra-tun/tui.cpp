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

#include "scitra/scitra-tun/scitra_tun.hpp"

#include <imtui/imtui.h>
#include <imtui/imtui-impl-ncurses.h>

#include <algorithm>
#include <chrono>
#include <cinttypes>
#include <cstdint>
#include <format>
#include <span>


namespace {

static const char* HELP_TEXT =
    "Scitra-TUN: A SCION-IP Translator in Userspace\n"
    "==============================================\n"
    "\n"
    "https://github.com/lschulz/scion-cpp/scitra\n"
    "https://github.com/netsys-lab/scion-ip-translator\n"
    "https://lcschulz.de/\n"
    "\n"
    "The user interface you are seeing is drawn with Dear ImGui and ImTui. The\n"
    "UI can be navigated using the keyboard and if supported by your terminal\n"
    "with a mouse. Use the arrow keys to navigate between UI elements, space\n"
    "to select/activate and ESC to return to the previous layer.\n"
    "\n"
    "Keys\n"
    "----\n"
    "F1  Shows this message\n"
    "F2  Changes the update speed\n"
    "F4  Brings up the path selection menu for the currently selected flow. Only\n"
    "    outgoing (active) flows can change their path. The menu shows the paths\n"
    "    after applying path policies.\n"
    "F5  Reloads the policy file if one was given with -p/--policy when Scitra-TUN\n"
    "    was started.\n"
    "F6  Fetches new paths for the destination of the currently selected flow.\n"
    "    Does not automatically select a new path or reevaluate the path policy.\n"
    "F9  Remove the currently selected flow resetting the path and path statistics.\n"
    "    The flow might get added again in the next refresh if there is still\n"
    "    traffic.\n"
    "F10 Close the UI and quit Scitra-TUN.\n"
    "F   Collapse/expand flows\n"
    "G   Collapse/expand graphs\n"
    "\n"
    "Header\n"
    "------\n"
    "The header shows the SCION host address of the system and the corresponding\n"
    "SCION-mapped IPv6 address. Below that are the total number of flows that are\n"
    "being translated and the address assigned to the TUN interface. Applications\n"
    "using the translator must bind to this address (or a wildcard). The third\n"
    "line shows the send and receive rate in packets and bits per second summed\n"
    "over all flows. Data rates are measured from TDP/UDP payload size not\n"
    "including protocol overhead.\n"
    "\n"
    "Flows\n"
    "-----\n"
    "List of active flows. The table contains the destination host addres, local\n"
    "and remote port, protocol type, the state of the flow as seen by Scitra-TUN,\n"
    "and packets/data rates. Flows can be sorted by clicking on the table headers.\n"
    "When a flow is selected, additional details are shown in the property window.\n"
    "\n"
    "Flow Properties\n"
    "Direction: Whether the translator actively picks paths for the flow or\n"
    "           passively responds on the same path as used by the remote host.\n"
    "TC       : Traffic class / DSCP of the last translated packet.\n"
    "Expiry   : Time until the path expires.\n"
    "Meta MTU : Path MTU reported by the path server. Zero if not available.\n"
    "Path MTU : Discovered Path MTU. May be smaller than the metadata MTU.\n"
    "MSS      : The flow's maximum segment size. The MSS des not take extension\n"
    "           headers or TCP options into account.\n"
    "Idle     : Time since the last packet. Flows are removed from the list if\n"
    "           there is no corresponding connected socket in the system anymore.\n"
    "           Flows from unconnected sockets expire after 2 minutes.\n"
    "\n"
    "Graphs\n"
    "------\n"
    "Application throughput of the selected flow. Shows the last 60 samples.\n"
    "\n";

constexpr std::size_t FLOW_RATE_HIST_LEN = 60;

enum TermKey
{
    F1 = 265,
    F2,
    F3,
    F4,
    F5,
    F6,
    F7,
    F8,
    F9,
    F10,
    F11,
    F12,
};

void ImGuiText(const std::string& str)
{
    ImGui::TextUnformatted(str.data(), str.data() + str.size());
}

void ImGuiSiQty(float value)
{
    if (value >= 1e9f) {
        ImGui::Text("%.2f G", 1e-9f * value);
    } else if (value >= 1e6f) {
        ImGui::Text("%.2f M", 1e-6f * value);
    } else if (value >= 1e3f) {
        ImGui::Text("%.2f K", 1e-3f * value);
    } else {
        ImGui::Text("%.2f  ", value);
    }
}

// Plot data over sample number as vertical bars.
void plotBars(const std::span<const float>& data, const char* title, int height)
{
    constexpr int MAX_LINE_LENGTH = 80;
    char line[MAX_LINE_LENGTH] = {};
    const char* eol = line + sizeof(line);

    const size_t dataSize = data.size();
    const int graphHeight = height - 2;
    if (graphHeight < 0) return;
    const int lineWidth = (int)dataSize + 8;
    if (lineWidth > MAX_LINE_LENGTH) return;

    auto max = std::ranges::max(data);
    char prefix = ' ';
    float multi = 1.0f;
    if (max > 0.0f) {
        if (max >= 1e9f) {
            prefix = 'G';
            multi = 1e-9f;
        } else if (max >= 1e6f) {
            prefix = 'M';
            multi = 1e-6f;
        } else if (max >= 1e3f) {
            prefix = 'K';
            multi = 1e-3f;
        } else if (max >= 1.0f) {
            prefix = ' ';
            multi = 1.0f;
        } else if (max >= 1e-3f) {
            prefix = 'm';
            multi = 1e3f;
        } else if (max >= 1e-3f) {
            prefix = 'u';
            multi = 1e6f;
        } else {
            prefix = 'n';
            multi = 1e9f;
        }
    }
    auto step = (multi * max) / (float)graphHeight;

    ImGui::BeginGroup();

    // Title
    auto t = ImGui::CalcTextSize(title).x;
    auto indent = 4 + (int)(0.5f * ((float)lineWidth - t));
    auto cur = std::format_to_n(line, sizeof(line), "{:>7} {:>{}}", prefix, title, indent).out;
    ImGui::TextUnformatted(line, cur);

    // Graph
    for (int y = graphHeight; y > 0; --y) {
        cur = std::format_to_n(line, sizeof(line), "{:7.2f} ", (float)y * step).out;
        for (size_t i = 0; i < dataSize && cur < eol; ++i) {
            if (multi * data[i] > (float)y * step)
                *cur++ = '|';
            else if (y == 1 && data[i] > 0)
                *cur++ = ':';
            else
                *cur++ = '.';
        }
        ImGui::TextUnformatted(line, cur);
    }

    // x-ticks
    cur = std::format_to_n(line, sizeof(line), "        1").out;
    if (dataSize >= 5)
        cur = std::format_to_n(cur, eol - cur, "{:>4}", 5).out;
    for (size_t i = 10; i <= dataSize; i += 5) {
        cur = std::format_to_n(cur, eol - cur, "{:>5}", i).out;
    }
    ImGui::TextUnformatted(line, eol);

    ImGui::EndGroup();
}

// Buffer holding the last N elements written to it.
template <typename T, std::size_t N>
class RollingBuffer
{
private:
    std::size_t pos = 0;
    std::array<T, N> buffer = {};

public:
    // Insert a new value at the end of the buffer.
    void push(const T& x)
    {
        if (++pos >= N) pos = 0;
        buffer[pos] = x;
    }

    // Get the last value written to the buffer.
    const T& last() const
    {
        return buffer[pos];
    }

    // Write the buffer contents in to output in newest to oldest order.
    template <typename U, typename Proj>
    void linearize(std::span<U, N> output, Proj proj)
    {
        std::size_t j = N - 1;
        for (std::size_t i = pos + 1; i < N; ++i)
            output[j--] = proj(buffer[i]);
        for (std::size_t i = 0; i <= pos; ++i)
            output[j--] = proj(buffer[i]);
    }
};

struct FlowRate
{
    FlowRate() = default;
    FlowRate(const FlowCounters& counters, float elapsed)
    {
        txPPS = (float)counters.pktsEgress / elapsed;
        txBPS = 8.0f * (float)counters.bytesEgress / elapsed;
        rxPPS = (float)counters.pktsIngress / elapsed;
        rxBPS = 8.0f * (float)counters.bytesIngress / elapsed;
    }

    float txPPS = 0.0f;
    float txBPS = 0.0f;
    float rxPPS = 0.0f;
    float rxBPS = 0.0f;
};

struct FlowListEntry
{
    FlowListEntry() = default;
    FlowListEntry(const FlowInfo& flow, float elapsed)
        : tuple(flow.tuple)
        , type(flow.type)
        , state(flow.state)
        , tc(flow.tc)
        , lastUsed(flow.lastUsed)
        , path(flow.path)
        , mtu(flow.mtu)
        , totalTxPkts(flow.counters.pktsEgress)
        , totalTxBytes(flow.counters.bytesEgress)
        , totalRxPkts(flow.counters.pktsIngress)
        , totalRxBytes(flow.counters.bytesIngress)
    {
        rate.push(FlowRate(flow.counters, elapsed));
    }

    void update(const FlowInfo& flow, float elapsed)
    {
        type = flow.type;
        state = flow.state;
        tc = flow.tc;
        lastUsed = flow.lastUsed;
        path = flow.path;
        mtu = flow.mtu;
        totalTxPkts += flow.counters.pktsEgress;
        totalTxBytes += flow.counters.bytesEgress;
        totalRxPkts += flow.counters.pktsIngress;
        totalRxBytes += flow.counters.bytesIngress;
        rate.push(FlowRate(flow.counters, elapsed));
    }

    // Calculate the flow's TCP or UDP MSS not taking optional SCION extension
    // headers into account.
    std::uint16_t mss() const
    {
        constexpr int SCION_SIZE = 28; // SCION common header with src/dst ISD-ASNs
        constexpr int TCP_SIZE = 20;   // TCP without options
        constexpr int UDP_SIZE = 8;

        int mss = mtu;
        mss -= SCION_SIZE;
        mss -= (int)tuple.src.host().size();
        mss -= (int)tuple.dst.host().size();
        if (path) mss -= (int)path->size();
        if (tuple.proto == hdr::ScionProto::TCP)
            mss -= TCP_SIZE;
        else if (tuple.proto == hdr::ScionProto::UDP)
            mss -= UDP_SIZE;

        return (std::uint16_t)std::max(0, mss);
    }

    FlowID tuple;
    FlowType type;
    FlowState state;
    std::uint8_t tc;
    std::chrono::steady_clock::time_point lastUsed;
    scion::PathPtr path;
    std::uint16_t mtu;
    std::uint64_t totalTxPkts;
    std::uint64_t totalTxBytes;
    std::uint64_t totalRxPkts;
    std::uint64_t totalRxBytes;
    RollingBuffer<FlowRate, FLOW_RATE_HIST_LEN> rate;
};

enum FlowColID
{
    FlowColID_Destination,
    FlowColID_Local,
    FlowColID_Remote,
    FlowColID_Proto,
    FlowColID_State,
    FlowColID_TXPkts,
    FlowColID_TXBits,
    FlowColID_RXPkts,
    FlowColID_RXBits,
};

void sortWithSortSpec(
    std::vector<std::unique_ptr<FlowListEntry>>& flowData, const ImGuiTableSortSpecs* sortSpecs)
{
    for (int i = 0; i < sortSpecs->SpecsCount; ++i) {
        switch (sortSpecs->Specs[i].ColumnUserID) {
        case FlowColID_Destination:
            if (sortSpecs->Specs[i].SortDirection == ImGuiSortDirection_Ascending)
                std::ranges::stable_sort(flowData, std::less<ScIPAddress>(), [] (auto& x) {
                    return x->tuple.dst.address();
                });
            else
                std::ranges::stable_sort(flowData, std::greater<ScIPAddress>(), [] (auto& x) {
                    return x->tuple.dst.address();
                });
            break;
        case FlowColID_Local:
            if (sortSpecs->Specs[i].SortDirection == ImGuiSortDirection_Ascending)
                std::ranges::stable_sort(flowData, std::less<std::uint16_t>(), [] (auto& x) {
                    return x->tuple.src.port();
                });
            else
                std::ranges::stable_sort(flowData, std::greater<std::uint16_t>(), [] (auto& x) {
                    return x->tuple.src.port();
                });
            break;
        case FlowColID_Remote:
            if (sortSpecs->Specs[i].SortDirection == ImGuiSortDirection_Ascending)
                std::ranges::stable_sort(flowData, std::less<std::uint16_t>(), [] (auto& x) {
                    return x->tuple.dst.port();
                });
            else
                std::ranges::stable_sort(flowData, std::greater<std::uint16_t>(), [] (auto& x) {
                    return x->tuple.dst.port();
                });
            break;
        case FlowColID_Proto:
            if (sortSpecs->Specs[i].SortDirection == ImGuiSortDirection_Ascending)
                std::ranges::stable_sort(flowData, std::less<int>(), [] (auto& x) {
                    return (int)x->tuple.proto;
                });
            else
                std::ranges::stable_sort(flowData, std::greater<int>(), [] (auto& x) {
                    return (int)x->tuple.proto;
                });
            break;
        case FlowColID_State:
            if (sortSpecs->Specs[i].SortDirection == ImGuiSortDirection_Ascending)
                std::ranges::stable_sort(flowData, std::less<int>(), [] (auto& x) {
                    return (int)x->state;
                });
            else
                std::ranges::stable_sort(flowData, std::greater<int>(), [] (auto& x) {
                    return (int)x->state;
                });
            break;
        case FlowColID_TXPkts:
            if (sortSpecs->Specs[i].SortDirection == ImGuiSortDirection_Ascending)
                std::ranges::stable_sort(flowData, std::less<float>(), [] (auto& x) {
                    return x->rate.last().txPPS;
                });
            else
                std::ranges::stable_sort(flowData, std::greater<float>(), [] (auto& x) {
                    return x->rate.last().txPPS;
                });
            break;
        case FlowColID_TXBits:
            if (sortSpecs->Specs[i].SortDirection == ImGuiSortDirection_Ascending)
                std::ranges::stable_sort(flowData, std::less<float>(), [] (auto& x) {
                    return x->rate.last().txBPS;
                });
            else
                std::ranges::stable_sort(flowData, std::greater<float>(), [] (auto& x) {
                    return x->rate.last().txBPS;
                });
            break;
        case FlowColID_RXPkts:
            if (sortSpecs->Specs[i].SortDirection == ImGuiSortDirection_Ascending)
                std::ranges::stable_sort(flowData, std::less<float>(), [] (auto& x) -> float {
                    return x->rate.last().rxPPS;
                });
            else
                std::ranges::stable_sort(flowData, std::greater<float>(), [] (auto& x) -> float {
                    return x->rate.last().rxPPS;
                });
            break;
        case FlowColID_RXBits:
            if (sortSpecs->Specs[i].SortDirection == ImGuiSortDirection_Ascending)
                std::ranges::stable_sort(flowData, std::less<float>(), [] (auto& x) -> float {
                    return x->rate.last().rxBPS;
                });
            else
                std::ranges::stable_sort(flowData, std::greater<float>(), [] (auto& x) -> float {
                    return x->rate.last().rxBPS;
                });
            break;
        }
    }
}

class ScitraTui
{
public:
    explicit ScitraTui(ScitraTun& scitra)
        : scitra(scitra)
        , lastUpdate(Clock::now())
    {
        IMGUI_CHECKVERSION();
        ImGui::CreateContext();

        auto& io = ImGui::GetIO();
        io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
        io.IniFilename = nullptr;
        io.LogFilename = nullptr;

        screen = ImTui_ImplNcurses_Init(true, 30);
        ImTui_ImplText_Init();

        auto& style = ImGui::GetStyle();
        style.Colors[ImGuiCol_Button] = ImVec4(0.25f, 0.25f, 0.25f, 1.0f);

        auto i = std::back_inserter(staticPorts);
        std::format_to(i, "Ports:");
        for (auto port : scitra.getStaticPorts())
            std::format_to(i, " {}", port);
    }

    ScitraTui(const ScitraTui&) = delete;
    ScitraTui(ScitraTui&&) = delete;
    ScitraTui operator=(const ScitraTui&) = delete;
    ScitraTui operator=(ScitraTui&&) = delete;

    ~ScitraTui()
    {
        ImTui_ImplText_Shutdown();
        ImTui_ImplNcurses_Shutdown();
    }

    void run()
    {
        using namespace std::chrono;
        while (scitra.running()) {
            auto now = Clock::now();
            auto elapsed = 1e-6f * (float)duration_cast<microseconds>(now - lastUpdate).count();
            auto diff = elapsed - (updateInterval[selInterval] - updateIntervalCorrection);
            if (diff > 0.0f) {
                updateFlows(elapsed);
                updateDebugInfo(elapsed);
                updateIntervalCorrection = diff;
                lastUpdate = now;
            }

            ImTui_ImplNcurses_NewFrame();
            ImTui_ImplText_NewFrame();
            ImGui::NewFrame();

            auto window = ImGui::GetMainViewport()->Size;
            if (window.x < 100 || window.y < 20) {
                ImGui::SetNextWindowPos(ImVec2(0, 0));
                ImGui::SetNextWindowSize(window);
                ImGui::Begin("Scitra-TUN", nullptr,
                    ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoBackground);
                ImGui::Text("Need at least an 100x20 characters");
                ImGui::End();
            } else {
                drawFrame(window);
            }

            ImGui::Render();
            ImTui_ImplText_RenderDrawData(ImGui::GetDrawData(), screen);
            ImTui_ImplNcurses_DrawScreen();
        }
    }

private:
    void updateFlows(float elapsed);
    void updateDebugInfo(float elapsed);

    void drawFrame(const ImVec2& window);
    void propertyWindow(const ImVec2& tabSize);

private:
    using Clock = std::chrono::high_resolution_clock;

    ScitraTun& scitra;
    ImTui::TScreen *screen = nullptr;
    Clock::time_point lastUpdate;

    // Static information
    std::string staticPorts;

    // Flows
    unsigned tcpFlows = 0;
    unsigned udpFlows = 0;
    unsigned otherFlows = 0;
    RollingBuffer<FlowRate, FLOW_RATE_HIST_LEN> globalRate;
    std::vector<std::unique_ptr<FlowListEntry>> flowData;

    // Debug Info
#if PERF_DEBUG == 1
    double egrProcessingTime = 0.0;
    double igrProcessingTime = 0.0;
#endif // PERF_DEBUG

    // Layout
    static constexpr float minWidthSideBySideGraphs = 145.0f;
    static constexpr float staticHeight = 8.0f; // height of fixed elements
    static constexpr float propertiesWidth = 50.0f;
    static constexpr int graphHeight = 8;
    static constexpr int pathPageSize = 10;

    // Data synchronization
    static inline const std::array<float, 4> updateInterval = {
        1.0f, 1/2.0f, 1/4.0f, 1/6.0f
    };
    int selInterval = 0;
    float updateIntervalCorrection = 0.0f;

    int selFlow = -1;
    bool sortFlows = false;
    bool flowsOpen = true;
    bool graphsOpen = true;
    bool showHelp = false;

    // Path pop-up
    bool pathSelector = false;
    struct PathSelWnd
    {
        enum {
            NO_FLOW_SELECTED,
            PASSIVE_FLOW,
            OPEN
        } state;
        FlowID flow;
        std::vector<PathPtr> paths;
        int selection = 0;
        int page = 0;
    } pathSel;
};

void ScitraTui::updateFlows(float elapsed)
{
    auto flows = scitra.exportFlows(true);
    std::vector<std::unique_ptr<FlowListEntry>> updated;
    updated.reserve(flows.size());

    void* selected = nullptr;
    if (selFlow >= 0 && (std::size_t)selFlow < flowData.size())
        selected = flowData[selFlow].get();
    selFlow = -1;

    tcpFlows = 0;
    udpFlows = 0;
    otherFlows = 0;
    FlowRate global = {};
    for (auto& flow : flows) {
        if (flow.tuple.proto == hdr::ScionProto::TCP)
            ++tcpFlows;
        else if (flow.tuple.proto == hdr::ScionProto::UDP)
            ++udpFlows;
        else
            ++otherFlows;
        global.txPPS += (float)flow.counters.pktsEgress;
        global.txBPS += 8.0f * (float)flow.counters.bytesEgress;
        global.rxPPS += (float)flow.counters.pktsIngress;
        global.rxBPS += 8.0f * (float)flow.counters.bytesIngress;

        auto i = std::ranges::find_if(flowData, [&flow] (auto& ptr) {
            return ptr && ptr->tuple == flow.tuple;
        });
        if (i != flowData.end()) {
            (*i)->update(flow, elapsed);
            if (i->get() == selected)
                selFlow = (int)updated.size();
            updated.push_back(std::move(*i));
        } else {
            updated.emplace_back(std::make_unique<FlowListEntry>(flow, elapsed));
        }
    }

    const float invElapsed = 1.0f / elapsed;
    global.txPPS *= invElapsed;
    global.txBPS *= invElapsed;
    global.rxPPS *= invElapsed;
    global.rxBPS *= invElapsed;
    flowData = std::move(updated);
    globalRate.push(global);
    sortFlows = true;
}

void ScitraTui::updateDebugInfo(float elapsed)
{
#if PERF_DEBUG == 1
    auto dbg = scitra.getDebugInfo();
    egrProcessingTime = (double)dbg.egrNanoSec / dbg.egrSamples;
    igrProcessingTime = (double)dbg.igrNanoSec / dbg.igrSamples;
#endif
}

void ScitraTui::drawFrame(const ImVec2& window)
{
    using namespace std::chrono;
    int totalGraphHeight = window.x >= minWidthSideBySideGraphs ? graphHeight : 2 * graphHeight;
    totalGraphHeight = graphsOpen * totalGraphHeight;

    ImGui::SetNextWindowPos(ImVec2(0, 0));
    ImGui::SetNextWindowSize(window);
    ImGui::Begin("Scitra-TUN", nullptr, ImGuiWindowFlags_NoDecoration);

    // Title
    auto drawList = ImGui::GetWindowDrawList();
    drawList->AddRectFilled(ImVec2(0, 0), ImVec2(window.x + 1, 0), IM_COL32(66, 150, 250, 79));
    const char* title = "Scitra-TUN";
    ImGui::SetCursorPosX(0.5f * (window.x - ImGui::CalcTextSize(title).x));
    ImGui::TextColored(ImVec4(1.0f, 1.0f, 1.0f, 1.0f), "%s", title);
    ImGui::SameLine();
    ImGui::SetCursorPosX(window.x - 10);
    ImGui::TextColored(ImVec4(1.0f, 1.0f, 1.0f, 1.0f), "%4.1f fps", ImGui::GetIO().Framerate);

    // Status line 1
    auto addr = std::format("Host address: {}%{}",
        scitra.getHostAddress(), scitra.getPublicIfaceName());
    ImGuiText(addr);
    ImGui::SameLine();
    ImGui::SetCursorPosX((float)std::max<std::size_t>(addr.size() + 1, 45));
    ImGuiText(std::format("Mapped : {}", scitra.getMappedAddress()));

    // Status line 2
    ImGui::Text("Flows: %3u UDP %3u TCP %3u other", udpFlows, tcpFlows, otherFlows);
    ImGui::SameLine();
    ImGui::SetCursorPosX((float)std::max<std::size_t>(addr.size() + 1, 45));
    ImGuiText(std::format("Bind to: {}%{}", scitra.getTunAddress(), scitra.getTunName()));

    // Status line 3
    const auto& total = globalRate.last();
    ImGui::Text("Total TX: %8.3f pkt/s %8.3f Mbit/s", total.txPPS, 1e-6 * total.txBPS);
    ImGui::SameLine();
    ImGui::SetCursorPosX(45);
    ImGui::Text("Total RX: %8.3f pkt/s %8.3f Mbit/s", total.rxPPS, 1e-6 * total.rxBPS);

    // Status line 4
#if PERF_DEBUG == 1
    ImGui::Text("Debug: TX = %10.4e ns RX = %10.4e ns", egrProcessingTime, igrProcessingTime);
    ImGui::SameLine();
    ImGui::SetCursorPosX(45);
#endif
    ImGuiText(staticPorts);

    // Flows
    ImGui::SetNextItemOpen(flowsOpen);
    if ((flowsOpen = ImGui::CollapsingHeader("Flows"))) {
        auto tabFlags = ImGuiTableFlags_ScrollY
            | ImGuiTableFlags_SizingFixedFit
            | ImGuiTableFlags_Sortable;
        ImVec2 tabSize(
            std::min(std::max(0.0f, window.x - propertiesWidth), 120.0f),
            window.y - staticHeight - (float)totalGraphHeight);
        if (ImGui::BeginTable("flows", 9, tabFlags, tabSize)) {
            ImGui::TableSetupScrollFreeze(0, 1);
            ImGui::TableSetupColumn("Destination", 0, 30, FlowColID_Destination);
            ImGui::TableSetupColumn("Local", ImGuiTableColumnFlags_DefaultSort, 6, FlowColID_Local);
            ImGui::TableSetupColumn("Remote", 0, 6, FlowColID_Remote);
            ImGui::TableSetupColumn("Proto", 0, 5, FlowColID_Proto);
            ImGui::TableSetupColumn("State", 0, 5, FlowColID_State);
            ImGui::TableSetupColumn("TX pkt/s", 0, 9, FlowColID_TXPkts);
            ImGui::TableSetupColumn("TX bit/s", 0, 9, FlowColID_TXBits);
            ImGui::TableSetupColumn("RX pkt/s", 0, 9, FlowColID_RXPkts);
            ImGui::TableSetupColumn("RX bit/s", 0, 9, FlowColID_RXBits);
            ImGui::TableHeadersRow();

            if (ImGuiTableSortSpecs* sortSpecs = ImGui::TableGetSortSpecs()) {
                if (sortFlows || sortSpecs->SpecsDirty) {
                    void* selected = nullptr;
                    if (selFlow >= 0 && (std::size_t)selFlow < flowData.size())
                        selected = flowData[selFlow].get();
                    sortWithSortSpec(flowData, sortSpecs);
                    // restore previous selection
                    if (selected) {
                        selFlow = 0;
                        for (auto& flow : flowData) {
                            if (flow.get() == selected) break;
                            ++selFlow;
                        }
                    }
                    sortFlows = false;
                    sortSpecs->SpecsDirty = false;
                }
            }

            ImGuiListClipper clipper;
            clipper.Begin((int)flowData.size());
            while (clipper.Step()) {
                for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; ++row) {
                    const auto& flow = flowData[row];
                    ImGui::PushID(row);
                    ImGui::TableNextRow(ImGuiTableRowFlags_None, 1.0f);

                    ImGui::TableNextColumn();
                    const int selFlags = ImGuiSelectableFlags_SpanAllColumns;
                    auto dst = std::format("{}", flow->tuple.dst.address());
                    if (ImGui::Selectable(dst.c_str(), selFlow == row, selFlags, ImVec2(0, 1.0f))) {
                        if (selFlow == row)
                            selFlow = -1; // deselect on second click
                        else
                            selFlow = row;
                    }

                    ImGui::TableNextColumn();
                    ImGui::Text("%u", (unsigned)flow->tuple.src.port());
                    ImGui::TableNextColumn();
                    ImGui::Text("%u", (unsigned)flow->tuple.dst.port());

                    ImGui::TableNextColumn();
                    ImGui::Text("%s", toString((int)flow->tuple.proto));

                    ImGui::TableNextColumn();
                    ImGui::TextUnformatted(toString(flow->state));

                    ImGui::TableNextColumn();
                    ImGuiSiQty(flow->rate.last().txPPS);
                    ImGui::TableNextColumn();
                    ImGuiSiQty(flow->rate.last().txBPS);
                    ImGui::TableNextColumn();
                    ImGuiSiQty(flow->rate.last().rxPPS);
                    ImGui::TableNextColumn();
                    ImGuiSiQty(flow->rate.last().rxBPS);
                    ImGui::PopID();
                }
            }
            ImGui::EndTable();
        }
        ImGui::SameLine();
        propertyWindow(tabSize);
    }

    // Graphs
    ImGui::SetNextItemOpen(graphsOpen);
    if ((graphsOpen = ImGui::CollapsingHeader("Graphs"))) {
        static std::array<float, FLOW_RATE_HIST_LEN> txAry, rxAry;
        std::span<float, FLOW_RATE_HIST_LEN> tx(txAry.data(), txAry.size());
        std::span<float, FLOW_RATE_HIST_LEN> rx(rxAry.data(), rxAry.size());
        if (selFlow < 0 || (std::size_t)selFlow >= flowData.size()) {
            globalRate.linearize(tx, [] (auto& x) {
                return x.txBPS;
            });
            globalRate.linearize(rx, [] (auto& x) {
                return x.rxBPS;
            });
        } else {
            flowData[selFlow]->rate.linearize(tx, [] (auto& x) {
                return x.txBPS;
            });
            flowData[selFlow]->rate.linearize(rx, [] (auto& x) {
                return x.rxBPS;
            });
        }
        plotBars(std::span<const float>(tx.data(), tx.size()), "TX bit/s", graphHeight);
        if (window.x >= minWidthSideBySideGraphs) {
            ImGui::SameLine();
            ImGui::SetCursorPosX(ImGui::GetCursorPosX() - 8.0f);
        }
        plotBars(std::span<const float>(rx.data(), rx.size()), "RX bit/s", graphHeight);
    }

    // Buttons at the bottom of the screen
    ImVec2 bottom(0, window.y - 1);
    ImGui::SetCursorPos(bottom);
    drawList->AddRectFilled(bottom, ImVec2(window.x + 1, bottom.y), IM_COL32(66, 150, 250, 79));
    if (ImGui::Button("F1 Help", {12, 1}) || ImGui::IsKeyDown(TermKey::F1)) {
        showHelp = !showHelp;
    }
    ImGui::SameLine();
    auto label = std::format("F2 Speed 1/{}s", (int)(1.0f / updateInterval[selInterval]));
    if (ImGui::Button(label.c_str(), {16, 1}) || ImGui::IsKeyDown(TermKey::F2)) {
        if ((std::size_t)++selInterval >= updateInterval.size()) selInterval = 0;
    }
    ImGui::SameLine();
    if (ImGui::Button("F4 Paths", {12, 1}) || ImGui::IsKeyDown(TermKey::F4)) {
        pathSelector = !pathSelector;
        if (pathSelector && selFlow >= 0 && (std::size_t)selFlow < flowData.size()) {
            const auto& flow = flowData[selFlow];
            if (flow->type == FlowType::Active) {
                pathSel.flow = flow->tuple;
                pathSel.paths = scitra.getPaths(pathSel.flow, flow->tc);
                pathSel.selection = -1;
                pathSel.page = 0;
                if (flow->path) {
                    auto i = std::ranges::find(pathSel.paths, flow->path->digest(), [] (auto& ptr) {
                        return ptr->digest();
                    });
                    if (i != pathSel.paths.end()) {
                        pathSel.selection = (int)std::distance(pathSel.paths.begin(), i);
                    }
                }
                pathSel.state = PathSelWnd::OPEN;
            } else {
                pathSel.state = PathSelWnd::PASSIVE_FLOW;
            }
        } else {
            pathSel.state = PathSelWnd::NO_FLOW_SELECTED;
        }
    }
    ImGui::SameLine();
    if (ImGui::Button("F5 Reload Policy", {19, 1}) || ImGui::IsKeyDown(TermKey::F5)) {
        ImGui::OpenPopup("Reload?");
    }
    ImGui::SameLine();
    if (ImGui::Button("F6 Refresh Paths", {19, 1}) || ImGui::IsKeyDown(TermKey::F6)) {
        if (selFlow >= 0 && (std::size_t)selFlow < flowData.size()) {
            scitra.refreshPaths(flowData[selFlow]->tuple.dst.isdAsn());
        } else {
            ImGui::OpenPopup("NoSelection");
        }
    }
    ImGui::SameLine();
    if (ImGui::Button("F9 Remove", {12, 1}) || ImGui::IsKeyDown(TermKey::F9)) {
        if (selFlow >= 0 && (std::size_t)selFlow < flowData.size()) {
            scitra.removeFlow(flowData[selFlow]->tuple);
        } else {
            ImGui::OpenPopup("NoSelection");
        }
    }
    ImGui::SameLine();
    if (ImGui::Button("F10 Quit", {12, 1}) || ImGui::IsKeyDown(TermKey::F10)) {
        scitra.stop();
    }

    if (ImGui::IsKeyDown('f')) {
        flowsOpen = !flowsOpen;
    } else if (ImGui::IsKeyDown('g')) {
        graphsOpen = !graphsOpen;
    }

    // Help pop-up
    if (showHelp) {
        ImVec2 size(82.0f, window.y - 10.0f);
        ImGui::SetNextWindowSize(size);
        ImGui::SetNextWindowPos(ImVec2(0.5f * (window.x - size.x), 0.5f * (window.y - size.y)));
        if (ImGui::Begin("Help", &showHelp, ImGuiWindowFlags_None | ImGuiWindowFlags_NoCollapse)) {
            ImGui::TextUnformatted(HELP_TEXT);
        }
        if (ImGui::IsKeyDown(ImGui::GetIO().KeyMap[ImGuiKey_Escape])) showHelp = false;
        ImGui::End();
    }

    // Path selector pop-up
    if (pathSelector) {
        ImVec2 size(std::min(window.x - 20.0f, 160.0f), window.y - 10.0f);
        ImGui::SetNextWindowSize(size);
        ImGui::SetNextWindowPos(ImVec2(0.5f * (window.x - size.x), 0.5f * (window.y - size.y)));
        if (ImGui::Begin("Paths", &pathSelector, ImGuiWindowFlags_NoCollapse)) {
            if (pathSel.state == PathSelWnd::NO_FLOW_SELECTED) {
                ImGui::TextUnformatted("No flow selected.");
            } else if (pathSel.state == PathSelWnd::PASSIVE_FLOW) {
                ImGui::TextUnformatted("Passive flow selected, path is chosen by remote host.");
            } else {
                auto size = ImGui::GetContentRegionAvail();
                size.y -= 2;
                ImGui::BeginChild("ScrollablePaths", size);
                auto begin = (int)(pathSel.page * pathPageSize);
                auto end = std::min(begin + pathPageSize, (int)pathSel.paths.size());
                for (int i = begin; i < end; ++i) {
                    ImGui::RadioButton(std::format("Path {}: ", i).c_str(), &pathSel.selection, i);
                    if (pathSel.paths[i]->broken()) {
                        ImGui::SameLine();
                        ImGui::TextColored(ImVec4(1.f, 0.f, 0.f, 1.f), "broken");
                    }
                    ImGui::SameLine();
                    ImGui::TextWrapped("%s", std::format("{}", *pathSel.paths[i]).c_str());
                }
                ImGui::EndChild();
            }
            ImGui::NewLine();
            if (ImGui::Button("(P)rev Page") || ImGui::IsKeyDown('p')) {
                pathSel.page = std::max(pathSel.page - 1, 0);
            }
            ImGui::SameLine();
            if (ImGui::Button("(N)ext Page") || ImGui::IsKeyDown('n')) {
                if (pathSel.paths.size() > 0) {
                    int pages = ((int)pathSel.paths.size() - 1) / pathPageSize;
                    pathSel.page = std::min(pathSel.page + 1, pages);
                }
            }
            ImGui::SameLine();
            if (ImGui::Button("Apply (Enter)") || ImGui::IsKeyDown(ImGui::GetIO().KeyMap[ImGuiKey_Enter])) {
                if (pathSel.selection >= 0 && (std::size_t)pathSel.selection < pathSel.paths.size()) {
                    pathSel.paths[pathSel.selection]->setBroken(0);
                    scitra.overrideFlowPath(pathSel.flow, pathSel.paths[pathSel.selection]);
                }
                pathSel.paths.clear();
                pathSel.selection = -1;
                pathSelector = false;
            }
            if (ImGui::IsKeyDown(ImGui::GetIO().KeyMap[ImGuiKey_Escape])) pathSelector = false;
        } else {
            pathSel.paths.clear();
            pathSel.selection = -1;
            pathSel.page = 0;
        }
        ImGui::End();
    }

    // Policy reload confirmation
    if (ImGui::BeginPopup("Reload?")) {
        ImGui::Text("Reload path policy?");
        if (ImGui::Button("Yes")) {
            scitra.reloadPathPolicy();
            ImGui::CloseCurrentPopup();
        }
        ImGui::SameLine();
        if (ImGui::Button("No")) {
            ImGui::CloseCurrentPopup();
        }
        ImGui::EndPopup();
    }

    // No selected flow warning
    if (ImGui::BeginPopup("NoSelection")) {
        // string gets cut off early without the trailing space
        ImGui::TextColored(ImVec4(1.f, 0.f, 0.f, 1.f), "No flow selected ");
        ImGui::EndPopup();
    }

    ImGui::End();
}

// Line wrap a SCION address.
std::string wrapScAddress(const std::string_view& sv, std::size_t width)
{
    std::stringstream stream;
    std::size_t lineBegin = 0;
    std::size_t lineEnd = 0;
    std::size_t lineLength = 0;
    const std::size_t size = sv.size();

    for (std::size_t i = 0; i < size; ++i) {
        if (sv[i] == ':') lineEnd = i + 1;
        if (++lineLength > width) {
            if (lineBegin > 0) stream << '\n';
            stream << sv.substr(lineBegin, lineEnd - lineBegin);
            lineBegin = lineEnd;
            lineLength = 0;
        }
    }
    if (lineBegin < size) {
        if (lineBegin > 0) stream << '\n';
        stream << sv.substr(lineBegin, size - lineBegin);
    }
    return stream.str();
}

void ScitraTui::propertyWindow(const ImVec2& tabSize)
{
    using namespace std::chrono;

    if (ImGui::BeginChild("PropertyWnd", {propertiesWidth, tabSize.y}, true)) {
        if (selFlow < 0 || (std::size_t)selFlow >= flowData.size()) {
            ImGui::TextUnformatted("No flow selected");
        } else {
            int flags = ImGuiTableFlags_ScrollY | ImGuiTableFlags_SizingFixedFit;
            if (ImGui::BeginTable("Properties", 2, flags)) {
                const auto& flow = flowData[selFlow];
                const std::size_t propertyWidth = 33;
                ImGui::TableSetupScrollFreeze(0, 1);
                ImGui::TableSetupColumn("Property", ImGuiTableColumnFlags_None, 10);
                ImGui::TableSetupColumn("Value", ImGuiTableColumnFlags_WidthStretch);
                ImGui::TableHeadersRow();

                ImGui::TableNextRow(ImGuiTableRowFlags_None, 1.0f);
                ImGui::TableNextColumn();
                ImGui::Text("Local Addr");
                {
                    ImGui::TableNextColumn();
                    auto str = std::format("{}", flow->tuple.src);
                    if (str.size() > propertyWidth) str = wrapScAddress(str, propertyWidth);
                    ImGuiText(str);
                }

                ImGui::TableNextRow(ImGuiTableRowFlags_None, 1.0f);
                ImGui::TableNextColumn();
                ImGui::Text("Remote Addr");
                {
                    ImGui::TableNextColumn();
                    auto str = std::format("{}", flow->tuple.dst);
                    if (str.size() > propertyWidth) str = wrapScAddress(str, propertyWidth);
                    ImGuiText(str);
                }

                ImGui::TableNextRow(ImGuiTableRowFlags_None, 1.0f);
                ImGui::TableNextColumn();
                ImGui::Text("State");
                ImGui::TableNextColumn();
                ImGui::TextUnformatted(toString(flow->state));

                ImGui::TableNextRow(ImGuiTableRowFlags_None, 1.0f);
                ImGui::TableNextColumn();
                ImGui::Text("Direction");
                ImGui::TableNextColumn();
                if (flow->type == FlowType::Active)
                    ImGui::TextUnformatted("Out / Active");
                else
                    ImGui::TextUnformatted("In / Passive");

                ImGui::TableNextRow(ImGuiTableRowFlags_None, 1.0f);
                ImGui::TableNextColumn();
                ImGui::Text("TC");
                ImGui::TableNextColumn();
                ImGui::Text("%u", (unsigned)flow->tc);

                if (flow->path) {
                    ImGui::TableNextRow(ImGuiTableRowFlags_None, 1.0f);
                    ImGui::TableNextColumn();
                    ImGui::Text("Path");
                    ImGui::TableNextColumn();
                    ImGui::TextWrapped("%s", std::format("{}", *flow->path).c_str());

                    ImGui::TableNextRow(ImGuiTableRowFlags_None, 1.0f);
                    ImGui::TableNextColumn();
                    ImGui::Text("Hops");
                    ImGui::TableNextColumn();
                    ImGui::Text("%u", flow->path->hopCount());

                    ImGui::TableNextRow(ImGuiTableRowFlags_None, 1.0f);
                    ImGui::TableNextColumn();
                    ImGui::Text("Expiry");
                    ImGui::TableNextColumn();
                    float expiry = std::numeric_limits<float>::infinity();
                    if (!flow->path->empty()) {
                        expiry = 1e-3f * (float)duration_cast<milliseconds>(
                            flow->path->expiry() - utc_clock::now()).count();
                    }
                    ImGui::Text("%.1f s", expiry);

                    ImGui::TableNextRow(ImGuiTableRowFlags_None, 1.0f);
                    ImGui::TableNextColumn();
                    ImGui::Text("Meta MTU");
                    ImGui::TableNextColumn();
                    ImGui::Text("%u", (unsigned)flow->path->mtu());
                }

                ImGui::TableNextRow(ImGuiTableRowFlags_None, 1.0f);
                ImGui::TableNextColumn();
                ImGui::Text("Path MTU");
                ImGui::TableNextColumn();
                ImGui::Text("%u", (unsigned)flow->mtu);

                ImGui::TableNextRow(ImGuiTableRowFlags_None, 1.0f);
                ImGui::TableNextColumn();
                ImGui::Text("MSS");
                ImGui::TableNextColumn();
                ImGui::Text("%u", (unsigned)flow->mss());

                ImGui::TableNextRow(ImGuiTableRowFlags_None, 1.0f);
                ImGui::TableNextColumn();
                ImGui::Text("Idle");
                ImGui::TableNextColumn();
                float idle = 1e-3f * (float)duration_cast<milliseconds>(
                    steady_clock::now() - flow->lastUsed).count();
                ImGui::Text("%.1f s", idle);

                ImGui::TableNextRow(ImGuiTableRowFlags_None, 1.0f);
                ImGui::TableNextColumn();
                ImGui::Text("TX Packets");
                ImGui::TableNextColumn();
                ImGui::Text("%" PRId64, flow->totalTxPkts);

                ImGui::TableNextRow(ImGuiTableRowFlags_None, 1.0f);
                ImGui::TableNextColumn();
                ImGui::Text("TX Bytes");
                ImGui::TableNextColumn();
                ImGui::Text("%" PRId64, flow->totalTxBytes);

                ImGui::TableNextRow(ImGuiTableRowFlags_None, 1.0f);
                ImGui::TableNextColumn();
                ImGui::Text("RX Packets");
                ImGui::TableNextColumn();
                ImGui::Text("%" PRId64, flow->totalRxPkts);

                ImGui::TableNextRow(ImGuiTableRowFlags_None, 1.0f);
                ImGui::TableNextColumn();
                ImGui::Text("RX Bytes");
                ImGui::TableNextColumn();
                ImGui::Text("%" PRId64, flow->totalRxBytes);

                ImGui::EndTable();
            }
        }
    }
    ImGui::EndChild();
}

} // anonymous namespace

void uiLoop(ScitraTun& app)
{
    ScitraTui{app}.run();
}
