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

#include "scion/details/bit.hpp"
#include "scion/details/debug.hpp"
#include "scion/error_codes.hpp"

#include <algorithm>
#include <array>
#include <cassert>
#include <concepts>
#include <cstdint>
#include <format>
#include <iostream>
#include <ostream>
#include <ranges>
#include <source_location>
#include <span>
#include <system_error>


/////////////////
// StreamError //
/////////////////

namespace scion {

/// \brief Passed to serialization methods to disable error context generation.
class NullStreamErrorT
{
public:
    bool error(const char* msg) { return false; }
    bool propagate() { return false; }
};

extern NullStreamErrorT NullStreamError;

/// \brief Class for optional serialization error reporting.
class StreamError
{
private:
    static constexpr std::size_t MAX_BACKTRACE = 12;

    struct TraceEntry
    {
        std::source_location loc;
        friend std::ostream& operator<<(std::ostream& stream, const TraceEntry& e)
        {
            stream << e.loc.file_name() << " (" << e.loc.line() << "): " << e.loc.function_name();
            return stream;
        }
    };

private:
    const char* message = nullptr;
    unsigned int backtraceSize = 0;
    bool overflow = false;
    std::array<TraceEntry, MAX_BACKTRACE> backtrace = {};

public:
    bool error(const char* msg, const std::source_location loc = std::source_location::current())
    {
        assert(message == nullptr);
        message = msg;
        return propagate(loc);
    }

    bool propagate(const std::source_location loc = std::source_location::current())
    {
        if (backtraceSize >= MAX_BACKTRACE) {
            overflow = true;
        } else {
            backtrace[backtraceSize] = TraceEntry{loc};
            backtraceSize += 1;
        }
        return false;
    }

    operator bool() const noexcept { return !message; }
    bool ok() const { return !message; }

    const char* getMessage() const noexcept { return message; }

    bool backtraceOverflow() const noexcept { return overflow; }
    auto getBacktrace() const noexcept { return std::views::take(backtrace, backtraceSize); }

    friend struct std::formatter<scion::StreamError>;
    friend struct std::formatter<scion::StreamError::TraceEntry>;

    friend std::ostream& operator<<(std::ostream& stream, const StreamError& e)
    {
        stream << "error: " << e.message << '\n';
        stream << "Backtrace:\n";
        for (unsigned int i = 0; i < e.backtraceSize; ++i) {
            stream << e.backtrace[i] << '\n';
        }
        return stream;
    }
};

} // namespace scion

template <>
struct std::formatter<scion::StreamError::TraceEntry>
{
    constexpr auto parse(auto& ctx)
    {
        return ctx.begin();
    }

    auto format(const scion::StreamError::TraceEntry& e, auto& ctx) const
    {
        return std::format_to(ctx.out(), "{} ({}): {}",
            e.loc.file_name(), e.loc.line(), e.loc.function_name());
    }
};

template <>
struct std::formatter<scion::StreamError>
{
    constexpr auto parse(auto& ctx)
    {
        return ctx.begin();
    }

    auto format(const scion::StreamError& e, auto& ctx) const
    {
        auto out = ctx.out();
        out = std::format_to(out, "error: {}\nBacktrace:\n", e.message);
        for (unsigned int i = 0; i < e.backtraceSize; ++i) {
            out = std::format_to(out, "{}\n", e.backtrace[i]);
        }
        return out;
    }
};

////////////////
// ReadStream //
////////////////

namespace scion {

/// \brief Bit stream for reading from a packet.
class ReadStream
{
private:
    std::span<const std::byte> data;
    std::span<const std::byte>::iterator byteIter;
    std::size_t bitPos = 0;

public:
    static constexpr bool IsReading = true;
    static constexpr bool IsWriting = !IsReading;
    static constexpr std::size_t npos = -1;

    ReadStream() = default;
    explicit ReadStream(std::span<const std::byte> buffer)
        : data(buffer), byteIter(buffer.begin()), bitPos(0)
    {}

    std::pair<std::size_t, std::size_t> getPos() const
    {
        return std::make_pair(byteIter - data.begin(), bitPos);
    }

    const std::byte* getPtr() const
    {
        assert(bitPos == 0);
        return &(*byteIter);
    }

    bool seek(std::size_t byteOffset, std::size_t bitOffset)
    {
        if (byteOffset == npos) {
            if (bitOffset != 0) return false;
            byteIter = data.end();
            bitPos = 0;
            return true;
        }
        if (bitOffset > 8) return false;
        if (byteOffset > data.size()) return false;
        if (byteOffset == data.size() && bitOffset > 0) return false;
        byteIter = data.begin() + byteOffset;
        bitPos = bitOffset;
        return true;
    }

    operator bool() const
    {
        return byteIter != data.end();
    }

    /// \brief Obtain a view of the next bytes to be read without advancing the
    /// extraction pointer. Can only be called when the extraction pointer falls
    /// on a byte boundary.
    /// \param view View of the data to be read.
    /// \param bytes Number of bytes to retrieve. If set to `npos` the
    /// resulting view contains all bytes from the current extraction position
    /// to the end of the underlying buffer.
    template <typename Error>
    bool lookahead(std::span<const std::byte>& view, std::size_t bytes, Error& err)
    {
        if (bitPos != 0) return err.error("alignment error");
        if (bytes == npos) {
            view = std::span<const std::byte>(byteIter, data.end());
            return true;
        }
        if (static_cast<std::size_t>(data.end() - byteIter) < bytes)
            return err.error("out of data to read");
        view = std::span<const std::byte>(byteIter, byteIter + bytes);
        return true;
    }

    template <std::unsigned_integral T, typename Error>
    bool serializeBits(T& value, std::size_t bits, Error& err)
    {
        if (bits == 0) {
            value = 0;
            return true;
        }
        constexpr std::size_t value_bits = 8 * sizeof(T);
        if (bits > std::min<std::size_t>(64u - 7u, value_bits))
            return err.error("invalid argument");

        std::size_t nBytes = (bits + bitPos + 7) / 8;
        if ((std::size_t)(data.end() - byteIter) < nBytes)
            return err.error("out of data to read");

        // read bytes as big endian
        std::uint64_t word = 0;
        std::copy_n(byteIter, nBytes, reinterpret_cast<std::byte*>(&word));
        word = details::byteswapBE(word);

        word <<= bitPos; // shift out already read bits from first byte
        word >>= (64 - bits); // shift MSBs down into least significant position

        value = static_cast<T>(word);
        byteIter += (bitPos + bits) / 8;
        bitPos = (bitPos + bits) % 8;
        return true;
    }

    template <typename Error>
    bool advanceBits(std::size_t bits, Error& err)
    {
        std::uint32_t value;
        for (std::size_t i = 0; i < (bits / 32); ++i) {
            if (!serializeBits(value, 32, err)) return err.propagate();
        }
        if (!serializeBits(value, bits % 32, err)) return err.propagate();
        return true;
    }

    template <typename Error>
    bool advanceBytes(std::size_t bytes, Error& err)
    {
        if (bitPos != 0)
            if (!advanceBits(8 * bytes, err)) return err.propagate();
        if ((std::size_t)(data.end() - byteIter) < bytes)
            return err.error("out of data to read");
        byteIter += bytes;
        return true;
    }

    template <std::unsigned_integral T, typename Error>
    bool serializeByte(T& value, Error& err)
    {
        bool res = false;
        std::uint32_t temp = 0;
        if (bitPos != 0) {
            res = serializeBits(temp, 8, err);
        } else {
            if (static_cast<std::size_t>(data.end() - byteIter) < 1)
                return err.error("out of data to read");
            std::copy_n(byteIter, 1, reinterpret_cast<std::byte*>(&temp));
            byteIter += 1;
            res = true;
        }
        value = static_cast<T>(temp);
        return res;
    }

    template <std::integral T, typename Error>
    bool serializeUint16(T& value, Error& err)
    {
        bool res = false;
        std::uint32_t temp = 0;
        if (bitPos != 0) {
            res = serializeBits(temp, 16, err);
        } else {
            if (static_cast<std::size_t>(data.end() - byteIter) < 2)
                return err.error("out of data to read");
            std::copy_n(byteIter, 2, reinterpret_cast<std::byte*>(&temp));
            byteIter += 2;
            res = true;
        }
        value = details::byteswapBE(static_cast<T>(temp));
        return res;
    }

    template <std::integral T, typename Error>
    bool serializeUint32(T& value, Error& err)
    {
        bool res = false;
        std::uint32_t temp = 0;
        if (bitPos != 0) {
            res = serializeBits(temp, 32, err);
        } else {
            if (static_cast<std::size_t>(data.end() - byteIter) < 4)
                return err.error("out of data to read");
            std::copy_n(byteIter, 4, reinterpret_cast<std::byte*>(&temp));
            byteIter += 4;
            res = true;
        }
        value = details::byteswapBE(static_cast<T>(temp));
        return res;
    }

    template <std::integral T, typename Error>
    bool serializeUint64(T& value, Error& err)
    {
        std::uint64_t temp = 0;
        if (bitPos != 0) return err.error("not implemented");
        if (static_cast<std::size_t>(data.end() - byteIter) < 8)
            return err.error("out of data to read");
        std::copy_n(byteIter, 8, reinterpret_cast<std::byte*>(&temp));
        byteIter += 8;
        value = details::byteswapBE(static_cast<T>(temp));
        return true;
    }

    template <typename Error>
    bool serializeBytes(std::span<std::byte> bytes, Error& err)
    {
        if (bitPos != 0) return err.error("not implemented");
        if (static_cast<std::size_t>(data.end() - byteIter) < bytes.size())
            return err.error("out of data to read");
        std::copy_n(byteIter, bytes.size(), bytes.begin());
        byteIter += bytes.size();
        return true;
    }
};

} // namespace scion

/////////////////
// WriteStream //
/////////////////

namespace scion {

/// \brief Bit stream for writing to a packet.
class WriteStream
{
private:
    std::span<std::byte> data;
    std::span<std::byte>::iterator byteIter;
    std::size_t bitPos = 0;

public:
    static constexpr bool IsReading = false;
    static constexpr bool IsWriting = !IsReading;
    static constexpr std::size_t npos = -1;

    WriteStream() = default;
    explicit WriteStream(std::span<std::byte> buffer)
        : data(buffer), byteIter(buffer.begin()), bitPos(0)
    {}

    // Disallow copying, because it usually is a bug
    WriteStream(WriteStream&) = delete;
    WriteStream& operator=(WriteStream&) = delete;

    std::pair<std::size_t, std::size_t> getPos() const
    {
        return std::make_pair(byteIter - data.begin(), bitPos);
    }

    std::byte* getPtr() const
    {
        assert(bitPos == 0);
        return &(*byteIter);
    }

    bool seek(std::size_t byteOffset, std::size_t bitOffset)
    {
        if (byteOffset == npos) {
            if (bitOffset != 0) return false;
            byteIter = data.end();
            bitPos = 0;
            return true;
        }
        if (bitOffset > 8) return false;
        if (byteOffset > data.size()) return false;
        if (byteOffset == data.size() && bitOffset > 0) return false;
        byteIter = data.begin() + byteOffset;
        bitPos = bitOffset;
        return true;
    }

    operator bool() const
    {
        return byteIter != data.end();
    }

    /// \brief Obtain a read-only view of the bytes already written relative to
    /// the current write pointer. Can only be called when the write pointer
    /// falls on a byte boundary.
    /// \param view View of the data.
    /// \param bytes Number of bytes to retrieve. If set to `npos` the
    /// resulting view contains all bytes from the beginning of the underlying
    /// buffer to the current write position.
    template <typename Error>
    bool lookback(std::span<const std::byte>& view, std::size_t bytes, Error& err)
    {
        if (bitPos != 0) return err.error("alignment error");
        if (bytes == npos) {
            view = std::span<const std::byte>(data.begin(), byteIter);
            return true;
        }
        if (static_cast<std::size_t>(byteIter - data.begin()) < bytes)
            return err.error("attempted to read out of bounds");
        view = std::span<const std::byte>(byteIter - bytes, byteIter);
        return true;
    }

    /// \brief Update a 16-bit checksum that has already been written by
    /// returning to a previous write position and overwriting. This function
    /// does not move the current write pointer forward and can only be called
    /// when the write pointer falls on a byte boundary.
    /// \param chksum New checksum value.
    /// \param offset Number of bytes that have been written since the after
    /// the target checksum was added.
    template <typename Error>
    bool updateChksum(std::uint16_t chksum, std::size_t offset, Error& err)
    {
        if (bitPos != 0) return err.error("alignment error");
        offset += 2; // go to start of the checksum
        if (static_cast<std::size_t>(byteIter - data.begin()) < offset)
            return err.error("attempted to write out of bounds");
        auto oldByteIter = byteIter;
        byteIter -= offset;
        bool result = serializeUint16(chksum, err);
        byteIter = oldByteIter;
        return result;
    }

    template <std::integral T, typename Error>
    bool serializeBits(T value, std::size_t bits, Error& err)
    {
        if (bits == 0) return true;
        constexpr std::size_t value_bits = 8 * sizeof(T);
        if (bits > std::min<std::size_t>(64u - 7u, value_bits))
            return err.error("invalid argument");

        std::size_t nBytes = (bits + bitPos + 7) / 8;
        if ((std::size_t)(data.end() - byteIter) < nBytes)
            return err.error("out of space");

        std::uint64_t word = value;
        word <<= (64 - bits); // shift LSBs into most significant position
        if (bitPos != 0) {
            word >>= bitPos; // make space for bits that are already occupied
            word |= static_cast<std::uint64_t>(*byteIter) << 56; // merge occupied bits
        }

        word = details::byteswapBE(word);
        std::copy_n(reinterpret_cast<std::byte*>(&word), nBytes, byteIter);

        byteIter += (bitPos + bits) / 8;
        bitPos = (bitPos + bits) % 8;
        return true;
    }

    template <typename Error>
    bool advanceBits(std::size_t bits, Error& err)
    {
        for (std::size_t i = 0; i < (bits / 32); ++i) {
            if (!serializeBits(0, 32, err)) return err.propagate();
        }
        if (!serializeBits(0, bits % 32, err)) return err.propagate();
        return true;
    }

    template <typename Error>
    bool advanceBytes(std::size_t bytes, Error& err)
    {
        if (bitPos != 0)
            if (!advanceBits(8 * bytes, err)) return err.propagate();
        if ((std::size_t)(data.end() - byteIter) < bytes)
            return err.error("out of space");
        std::fill(byteIter, byteIter + bytes, std::byte{0});
        byteIter += bytes;
        return true;
    }

    template <typename Error>
    bool serializeByte(std::uint8_t value, Error& err)
    {
        if (bitPos != 0) {
            return serializeBits(value, 8, err);
        } else {
            if (static_cast<std::size_t>(data.end() - byteIter) < sizeof(value))
                return err.error("out of space");
            byteIter = std::copy_n(reinterpret_cast<std::byte*>(&value), sizeof(value), byteIter);
            return true;
        }
    }

    template <typename Error>
    bool serializeUint16(std::uint16_t value, Error& err)
    {
        value = details::byteswapBE(value);
        if (bitPos != 0) {
            return serializeBits(value, 16, err);
        } else {
            if (static_cast<std::size_t>(data.end() - byteIter) < sizeof(value))
                return err.error("out of space");
            byteIter = std::copy_n(reinterpret_cast<std::byte*>(&value), sizeof(value), byteIter);
        }
        return true;
    }

    template <typename Error>
    bool serializeUint32(std::uint32_t value, Error& err)
    {
        value = details::byteswapBE(value);
        if (bitPos != 0) {
            return serializeBits(value, 32, err);
        } else {
            if (static_cast<std::size_t>(data.end() - byteIter) < sizeof(value))
                return err.error("out of space");
            byteIter = std::copy_n(reinterpret_cast<std::byte*>(&value), sizeof(value), byteIter);
        }
        return true;
    }

    template <typename Error>
    bool serializeUint64(std::uint64_t value, Error& err)
    {
        value = details::byteswapBE(value);
        if (bitPos != 0) {
            return serializeBits(value, 32, err);
        } else {
            if (static_cast<std::size_t>(data.end() - byteIter) < sizeof(value))
                return err.error("out of space");
            byteIter = std::copy_n(reinterpret_cast<std::byte*>(&value), sizeof(value), byteIter);
        }
        return true;
    }

    template <typename Error>
    bool serializeBytes(std::span<const std::byte> bytes, Error& err)
    {
        if (bitPos != 0) return err.error("not implemented");
        if (static_cast<std::size_t>(data.end() - byteIter) < bytes.size())
            return err.error("out of space");
        byteIter = std::copy(bytes.begin(), bytes.end(), byteIter);
        return true;
    }
};

} // namespace scion
