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


struct Arguments
{
    std::string publicAddress;
    std::string publicInterface;
    std::string sciond = "127.0.0.1:30255";
    std::string tunDevice = "scion";
    std::string tunAddress;
    int underlayMtu = 0;
    int tunMtu = 0;
    std::vector<std::uint16_t> ports;
    int queues = 1;
    int threads = 1;
    std::filesystem::path policy;
    spdlog::level::level_enum logLevel = spdlog::level::warn;
    std::filesystem::path logFile;
    bool enableScmpDispatch = false;
    bool stun = false;
    std::uint16_t stunPort = 3478;
    std::uint32_t stunTimeout = 30;
    bool tui = false;
};
