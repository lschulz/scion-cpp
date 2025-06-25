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

#include "scion/addr/address.hpp"
#include "scion/addr/generic_ip.hpp"
#include "scion/hdr/scmp.hpp"
#include "scion/path/raw.hpp"

#include <span>


namespace scion {

/// \brief Interface of an SCMP handler.
class ScmpHandler
{
public:
    void handleScmp(
        const ScIPAddress& from,
        const RawPath& path,
        const hdr::ScmpMessage& msg,
        std::span<const std::byte> payload)
    {
        ScmpHandler* handler = this;
        while (handler) {
            if (!handler->handleScmpCallback(from, path, msg, payload)) return;
            handler = handler->nextScmpHandler();
        }
    }

    virtual ScmpHandler* nextScmpHandler() = 0;
    virtual void setNextScmpHandler(ScmpHandler* handler) = 0;

private:
    virtual bool handleScmpCallback(
        const ScIPAddress& from,
        const RawPath& path,
        const hdr::ScmpMessage& msg,
        std::span<const std::byte> payload) = 0;
};

/// \brief Helper for implementing SCMP handlers.
class ScmpHandlerImpl : public ScmpHandler
{
private:
    ScmpHandler* nextHandler = nullptr;

public:
    ScmpHandler* nextScmpHandler() override
    {
        return nextHandler;
    }

    void setNextScmpHandler(ScmpHandler* handler) override
    {
        nextHandler = handler;
    }
};

} // namespace scion
