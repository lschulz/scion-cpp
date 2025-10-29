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

#include "scitra/linux/error_codes.hpp"
#include "scion/error_codes.hpp"


struct ScitraErrorCategory : public std::error_category
{
    const char* name() const noexcept
    {
        return "scitra";
    }

    std::string message(int code) const
    {
        switch (static_cast<ScitraError>(code)) {
            case ScitraError::Ok:
                return "ok";
            case ScitraError::Cancelled:
                return "operation cancelled";
            case ScitraError::Exiting:
                return "application exiting";
            case ScitraError::LogicError:
                return "logic error";
            case ScitraError::PartialWrite:
                return "partial write";
            case ScitraError::InvalidArgument:
                return "invalid argument";
            case ScitraError::BufferTooSmall:
                return "provided buffer too small to hold output";
            case ScitraError::ProtocolNotSupported:
                return "protocol not supported";
            case ScitraError::SocketClosed:
                return "socket closed";
            case ScitraError::InterfaceNotFound:
                return "interface not found";
            default:
                return "unexpected error code";
        }
    }

    bool equivalent(int code, const std::error_condition& cond) const noexcept override
    {
        using scion::ErrorCondition;
        if (cond.category() == scion::scion_error_condition()) {
            const auto value = static_cast<ErrorCondition>(cond.value());
            switch (value) {
            case ErrorCondition::Ok:
                return code == (int)ScitraError::Ok;
            case ErrorCondition::Cancelled:
                return code == (int)ScitraError::Cancelled;
            case ErrorCondition::LogicError:
                return code == (int)ScitraError::LogicError;
            case ErrorCondition::InvalidArgument:
                return code == (int)ScitraError::InvalidArgument;
            case ErrorCondition::BufferTooSmall:
                return code == (int)ScitraError::BufferTooSmall;
            default:
                return false;
            }
        }
        return false;
    }
};

static ScitraErrorCategory scitraErrorCategory;

const std::error_category& scitra_error_category()
{
    return scitraErrorCategory;
}

std::error_code make_error_code(ScitraError code)
{
    return {static_cast<int>(code), scitraErrorCategory};
}
