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

#include "scion/details/bit.hpp"

#include "utilities.hpp"

#include <filesystem>
#include <fstream>
#include <string>


std::filesystem::path TEST_BASE_PATH;

void setTestBasePath(int argc, char* argv[])
{
    namespace fs = std::filesystem;

    char* env = std::getenv("TEST_BASE_PATH");
    if (argc > 1) {
        TEST_BASE_PATH = fs::path(argv[1]);
    } else if (env) {
        TEST_BASE_PATH = fs::path(env);
    } else {
        TEST_BASE_PATH = fs::current_path();
    }
}

std::vector<std::vector<std::byte>> loadPackets(const char* path)
{
    using namespace std::literals;
    std::vector<std::vector<std::byte>> packets;

    auto fullPath = TEST_BASE_PATH / path;
    std::ifstream file(fullPath, std::ios_base::binary);
    if (!file.is_open()) throw std::runtime_error("file not found: "s + fullPath.string());
    file.exceptions(std::ifstream::badbit);

    while (file.good()) {
        std::uint32_t length = 0;
        file.read(reinterpret_cast<char*>(&length), sizeof(length));
        auto gc = file.gcount();
        if (file.eof()) {
            if (gc == 0)
                break;
            else
                throw std::runtime_error("file too short: "s + path);
        }
        length = scion::details::byteswapBE(length);

        std::vector<std::byte> packet(length);
        file.read(reinterpret_cast<char*>(packet.data()), length);
        if (file.gcount() < length) throw std::runtime_error("file too short: "s + path);

        packets.push_back(packet);
    }

    return packets;
}
