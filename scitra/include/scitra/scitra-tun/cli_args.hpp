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

#pragma once

#include <CLI/CLI.hpp>
#include <spdlog/spdlog.h>

#include <cstdint>
#include <filesystem>
#include <string>


enum class Mode
{
    Normal,
    Gateway,
};

struct Arguments
{
    Mode mode = Mode::Normal;
    bool tui = false;
    bool xlatUnderlay = false;

    std::string publicAddress;
    std::string publicInterface;
    std::string tunAddress;
    std::string tunDevice = "scion";
    std::vector<std::string> extraAddresses;
    std::string sciond = "127.0.0.1:30255";
    bool enableScmpDispatch = false;
    std::vector<std::string> ports;

    int tunMtu = 0;
    int underlayMtu = 0;

    bool stun = false;
    std::uint16_t stunPort = 0;
    std::uint32_t stunTimeout = 30;

    std::filesystem::path policy;
    std::filesystem::path pidfile;

    int queues = 1;
    int threads = 1;

    spdlog::level::level_enum logLevel = spdlog::level::warn;
    std::filesystem::path logFile;
};
