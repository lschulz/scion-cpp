// Copyright (c) 2024-2026 Lars-Christian Schulz
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

#include <scion/scion_asio.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>

#include <boost/asio.hpp>

#include <chrono>


// Coroutine that tries getting a NAT mapping until a set number of retries
// has been reached.
inline boost::asio::awaitable<scion::Maybe<scion::ScIPEndpoint>> getStunMapping(
    scion::asio::UdpSocket& socket, const scion::asio::UdpSocket::UnderlayEp& router,
    std::chrono::milliseconds rto, unsigned int retry = 5)
{
    using namespace scion;
    using namespace boost::asio;
    using namespace boost::asio::experimental::awaitable_operators;

    steady_timer timer(co_await this_coro::executor, rto);
    for (unsigned int i = 0; i <= retry; ++i)
    {
        auto ec = co_await socket.requestStunMappingAsync(router, use_awaitable);
        if (ec) co_return Error(ec);

        boost::system::error_code syserr;
        auto res = co_await (timer.async_wait(redirect_error(use_awaitable, syserr))
            || socket.recvStunResponseAsync(use_awaitable));
        if (syserr && syserr != ErrorCondition::Cancelled) co_return Error(syserr);
        if (res.index() == 1) {
            ec = std::get<1>(res);
            if (ec == ErrorCode::StunReceived) co_return socket.mappedEp();
            else if (ec != ErrorCondition::Timeout) co_return Error(ec);
        }
        rto *= 2;
    }
    co_return Error(ErrorCode::Timeout);
}
