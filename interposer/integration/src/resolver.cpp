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

#if _WIN32
#include <ws2tcpip.h>
#define close closesocket
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#endif

#include <CLI/CLI.hpp>

#include <array>
#include <cstdlib>
#include <format>
#include <iostream>
#include <memory>

#define AF_SCION 64


int main(int argc, char* argv[])
{
    std::string name;
    std::string service;
    int family = AF_UNSPEC;
    int socktype = SOCK_DGRAM;
    int protocol = 0;

    CLI::App app{"Test interposing name resolution"};
    app.add_option("name", name, "Host name")->required();
    app.add_option("service", service, "Service name");
    app.add_option("-f,--family", family, "Address family");
    app.add_option("-t,--type", socktype, "Socket type");
    app.add_option("-p,--protocol", protocol, "Protocol");
    CLI11_PARSE(app, argc, argv);

    addrinfo* result;
    static addrinfo hints = {};
    hints.ai_family = family;
    hints.ai_socktype = socktype;
    hints.ai_protocol = protocol;
    hints.ai_flags = 0;
    int err = -1;
    if (service.empty())
        err = getaddrinfo(name.c_str(), nullptr, &hints, &result);
    else
        err = getaddrinfo(name.c_str(), service.c_str(), &hints, &result);
    if (err) {
        std::cerr << "getnameinfo returned " << err << " (" << gai_strerror(err) << ")\n";
        return EXIT_FAILURE;
    }
    std::unique_ptr<addrinfo, void(*)(addrinfo*)> defer(result, &freeaddrinfo);

    static std::array<char, 80> hostOut = {};
    static std::array<char, 8> serviceOut = {};
    for (addrinfo* cur = result; cur; cur = cur->ai_next) {
        int err = getnameinfo(cur->ai_addr, cur->ai_addrlen,
            hostOut.data(), hostOut.size(),
            serviceOut.data(), serviceOut.size(),
            NI_NUMERICHOST | NI_NUMERICSERV);
        if (err) {
            std::cerr << "getnameinfo returned " << err << " (" << gai_strerror(err) << ")\n";
            return EXIT_FAILURE;
        }
        std::cout << std::format("[{}]:{}\n", hostOut.data(), serviceOut.data());
    }
    return EXIT_SUCCESS;
}
