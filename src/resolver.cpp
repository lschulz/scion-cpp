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

#include "scion/resolver.hpp"
#include "scion/details/debug.hpp"

#include <ares.h>
#include <boost/algorithm/string.hpp>

#if __linux__
#include <arpa/nameser.h>
#elif _WIN32
constexpr int ns_c_in = 1;
constexpr int ns_t_txt = 16;
#endif

#include <fstream>


namespace scion {

#if _WIN32
const char* HOSTS_FILE = "%ProgramFiles%\\scion\\hosts";
#else
const char* HOSTS_FILE = "/etc/scion/hosts";
#endif

extern ScionErrorCondition scionErrorCondition;

} // namespace scion

struct CAresErrorCategory : public std::error_category
{
    const char* name() const noexcept override
    {
        return "c-ares";
    }

    std::string message(int code) const override
    {
        return std::string(ares_strerror(code));
    }

    bool equivalent(int code, const std::error_condition& cond) const noexcept override
    {
        using scion::ErrorCondition;
        if (cond.category() == scion::scionErrorCondition) {
            const auto value = static_cast<ErrorCondition>(cond.value());
            switch (value) {
            case ErrorCondition::Ok:
                return code == ARES_SUCCESS;
            case ErrorCondition::Cancelled:
                return code == ARES_EDESTRUCTION || code == ARES_ECANCELLED;
            case ErrorCondition::Timeout:
                return code == ARES_ETIMEOUT;
            case ErrorCondition::LogicError:
                return code == ARES_ENOTINITIALIZED;
            case ErrorCondition::InvalidArgument:
                return code == ARES_EBADNAME;
            case ErrorCondition::NameNotFound:
                return code == ARES_ENOTFOUND;
            case ErrorCondition::RemoteError:
                return code == ARES_ENODATA || code == ARES_EFORMERR
                    || code == ARES_ESERVFAIL || code == ARES_ENOTFOUND
                    || code == ARES_ENOTIMP || code == ARES_EREFUSED;
            default:
                return false;
            }
        }
        return false;
    }
};

CAresErrorCategory cAresErrorCategory;

std::error_code make_error_code(ares_status_t code)
{
    return {static_cast<int>(code), cAresErrorCategory};
}

namespace std {
template <> struct is_error_code_enum<ares_status_t> : true_type {};
}

namespace scion {

//////////////
// Resolver //
//////////////

class Resolver::Ares
{
private:
    ares_channel_t* channel = nullptr;
    friend class Resolver;

public:
    Ares() = default;
    ~Ares() { destroy(); }
    Ares(const Ares&) = delete;
    Ares(Ares&&) = delete;

    std::error_code initialize() noexcept
    {
        if (channel) return ErrorCode::Ok;

        auto res = (ares_status_t)ares_library_init(ARES_LIB_INIT_ALL);
        if (res != ARES_SUCCESS) return res;

        if (!ares_threadsafety()) {
            ares_library_cleanup();
            SCION_DEBUG_PRINT("c-ares not compiled with thread support\n");
            return ErrorCode::LogicError;
        }

        ares_options opts = {};
        opts.evsys = ARES_EVSYS_DEFAULT;
        int optmask = ARES_OPT_EVENT_THREAD;

        res = (ares_status_t)ares_init_options(&channel, &opts, optmask);
        if (res != ARES_SUCCESS) {
            ares_library_cleanup();
            return res;
        }
        return res;
    };

    void destroy() noexcept
    {
        if (!channel) return;
        ares_destroy(channel);
        channel = nullptr;
        ares_library_cleanup();
    }
};

Resolver::Resolver()
    : ares(new Ares)
    , hostsFile(HOSTS_FILE)
{}

Resolver::~Resolver() = default;

std::error_code Resolver::initialize()
{
    return ares->initialize();
}

void Resolver::cancel() const
{
    ares_cancel(ares->channel);
}

void Resolver::aresQueryTXT(const std::string& name, txtCallback* cb, void* arg) const
{
    ares_query(ares->channel, name.c_str(), ns_c_in, ns_t_txt, cb, arg);
}

auto Resolver::parseTxtRecords(int status, unsigned char* abuf, int alen) -> Maybe<AddressSet>
{
    Maybe<AddressSet> result;
    if (status) {
        result = Error((ares_status_t)status);
    } else {
        ares_txt_reply* reply = nullptr;
        status = ares_parse_txt_reply(abuf, alen, &reply);
        if (status) {
            result = Error((ares_status_t)status);
        } else {
            result = Error(ErrorCode::NameNotFound);
            for (ares_txt_reply* record = reply; record; record = record->next) {
                std::string_view sv(reinterpret_cast<char*>(record->txt), record->length);
                parseScionRecord(sv, result);
            }
            ares_free_data(reply);
        }
    }
    return result;
}

bool Resolver::parseScionRecord(std::string_view record, Maybe<AddressSet>& out)
{
    if (record.starts_with("scion=")) {
        record.remove_prefix(6);
        auto addr = ScIPAddress::Parse(record);
        if (addr.has_value()) {
            if (!out.has_value()) {
                out = std::vector<ScIPAddress>();
            }
            out->push_back(*addr);
            return true;
        }
    }
    return false;
}

////////////////////
// Free Functions //
////////////////////

Maybe<std::vector<ScIPAddress>> queryHostsFile(
    std::string_view name,
    const std::filesystem::path& hostsFilePath)
{
    Maybe<std::vector<ScIPAddress>> result = Error(ErrorCode::NameNotFound);
    std::fstream file(hostsFilePath);
    if (!file.is_open()) return result;

    auto finder = boost::algorithm::token_finder([] (char c) -> bool { return std::isspace(c); } );
    std::string line;
    while (std::getline(file, line)) {
        auto part = boost::algorithm::make_split_iterator(line, finder);
        decltype(part) end;
        if (part == end) continue; // empty line

        {
            std::string_view sv(part->begin(), part->end());
            if (sv.starts_with('#')) continue; // entire line is comment
            if (sv != name) continue; // not the name we're looking for
            ++part;
        }

        for (; part != end; ++part) {
            std::string_view sv(part->begin(), part->end());
            if (sv.starts_with('#')) break; // trailing comment
            auto addr = ScIPAddress::Parse(sv);
            if (addr.has_value()) {
                if (!result.has_value())
                    result = std::vector<ScIPAddress>();
                result->push_back(*addr);
            }
        }
    };
    return result;
}

} // namespace scion
