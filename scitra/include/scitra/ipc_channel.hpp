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

#include "scion/addr/generic_ip.hpp"
#include "scion/bit_stream.hpp"
#include "scion/error_codes.hpp"

#include <boost/asio.hpp>

#include <array>
#include <cstdint>
#include <span>


namespace scion {
namespace scitra {

using TxID = std::uint32_t;

class IpcMsgHeader
{
public:
    static constexpr std::size_t size = 16;
    std::uint32_t magic;
    std::uint32_t length = 0;
    std::uint32_t function = 0;
    std::uint32_t txId = 0;

public:
    template <typename Stream, typename Error>
    bool serialize(Stream& stream, Error& err)
    {
        if (!stream.serializeUint32(magic, err)) return err.propagate();
        if (!stream.serializeUint32(length, err)) return err.propagate();
        if (!stream.serializeUint32(function, err)) return err.propagate();
        if (!stream.serializeUint32(txId, err)) return err.propagate();
        return true;
    }
};

class IpcChannel
{
private:
    using local_stream = boost::asio::local::stream_protocol;
    local_stream::socket m_socket;
    const std::uint32_t m_magic;

public:
    template <typename Executor>
    IpcChannel(Executor& ex, std::uint32_t magic)
        : m_socket(ex), m_magic(magic)
    {}

    IpcChannel(local_stream::socket&& socket, std::uint32_t magic)
        : m_socket(std::move(socket)), m_magic(magic)
    {}

    std::error_code connect(std::string_view path)
    {
        boost::system::error_code ec;
        local_stream::endpoint ep(path);
        m_socket.connect(ep, ec);
        return ec;
    }

    std::error_code close()
    {
        boost::system::error_code ec;
        m_socket.close(ec);
        return ec;
    }

    bool isOpen() const { return m_socket.is_open(); }

    std::error_code send(
        std::uint32_t function,
        std::uint32_t transaction,
        std::span<std::byte> message)
    {
        namespace asio = boost::asio;

        IpcMsgHeader header;
        header.magic = 0;
        header.length = (std::uint32_t)message.size();
        header.function = function;
        header.txId = transaction;

        std::array<std::byte, IpcMsgHeader::size> hbuf;
        WriteStream ws(hbuf);
        if (!header.serialize(ws, NullStreamError)) {
            return ErrorCode::LogicError;
        }

        std::array<asio::const_buffer, 2> buffers = {asio::buffer(hbuf), asio::buffer(message)};
        boost::system::error_code ec;
        asio::write(m_socket, buffers, ec);
        return ec;
    }

    boost::asio::awaitable<std::tuple<
        std::span<std::byte>, // message
        std::uint32_t,        // function
        std::uint32_t,        // transaction ID
        std::error_code       // error
    >> receive(std::span<std::byte> buffer)
    {
        namespace asio = boost::asio;
        constexpr auto token = asio::as_tuple(asio::use_awaitable);

        // Read message header
        std::array<std::byte, IpcMsgHeader::size> hbuf;
        auto [ec, n] = co_await asio::async_read(m_socket, asio::buffer(hbuf), token);
        if (ec) co_return std::make_tuple(std::span<std::byte>(), 0, 0, ec);

        // Parse header
        IpcMsgHeader hdr;
        ReadStream rs(hbuf);
        if (!hdr.serialize(rs, NullStreamError) || hdr.magic != m_magic) {
            auto ec = ErrorCode::InvalidPacket;
            co_return std::make_tuple(std::span<std::byte>(), 0, 0, ec);
        }

        // Read message
        if (buffer.size() < hdr.length) {
            auto ec = ErrorCode::BufferTooSmall;
            co_return std::make_tuple(std::span<std::byte>(), 0, 0, ec);
        }
        std::tie(ec, n) = co_await asio::async_read(m_socket,
            asio::buffer(buffer, hdr.length), token);
        co_return std::make_tuple(buffer.subspan(n), hdr.function, hdr.txId, ec);
    }
};

} // namespace scitra
} // namespace scion
