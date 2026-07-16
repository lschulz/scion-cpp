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

#include <scion/scion.hpp>

#include <string>


struct ServerCfg
{
    bool verbose = false;
};

struct ClientCfg
{
    scion::ScIPEndpoint remote;
    float timeout = 1.0f;
    float period = 1.0f;
    std::uint8_t skip = 0;
    unsigned limit = 0;
    int path = -1;
    scion::idint::Instr instrs[4] = {};
    scion::idint::AM agrMode = scion::idint::AM::Off;
    scion::idint::AF agrFuncs[4] = {};
    bool stun = false;
    bool reqNodeId = false;
    bool reqNodeCnt = false;
    bool reqIgr = false;
    bool reqEgr = false;
    bool noVerify = false;
    bool encrypt = false;
    bool tui = false;
};

struct Config
{
    std::string sciond = "127.0.0.1:30255";
    scion::generic::IPEndpoint local;
    bool serverMode = false;
    ServerCfg server;
    ClientCfg client;
};
