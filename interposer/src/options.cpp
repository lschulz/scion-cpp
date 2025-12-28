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

#include "options.hpp"
#include "scion/error_codes.hpp"

#define TOML_EXCEPTIONS 0
#include <toml++/toml.hpp>
#include <re2/re2.h>

#include <unistd.h>

#include <array>
#include <filesystem>
#include <format>
#include <fstream>
#include <optional>
#include <string_view>


#if _WIN32
const char* DEFAULT_CONFIG_PATH = "%programdata%/scion/interposer.toml";
#else
const char* DEFAULT_CONFIG_PATH = "/etc/scion/interposer.toml";
#endif

static std::string _getenv(const char* var)
{
    // FIXME: getenv is not thread-safe
    const char* value = std::getenv(var);
    if (value) return value;
    else return std::string();
}

// Try to find the full path to the executable the interposer has been injected
// into.
static scion::Maybe<std::string> getExecutablePath()
{
    std::string path(256, '\0');
#ifdef _WIN32
    // TODO
#else
    std::array<const char*, 3> proc = {
        "/proc/self/exe",
        "/proc/curproc/file",
        "/proc/self/path/a.out"
    };
    int n = -1;
    for (auto&& link : proc) {
        n = (int)readlink(link, path.data(), path.size());
        if (n >= 0) {
            path.resize(n);
            return path;
        }
    }
    return scion::Error({errno, std::system_category()});
#endif
}

static std::optional<bool> parseBool(std::string_view str)
{
    if (str == "true" || str == "yes" || str == "on" || str == "1")
        return true;
    else if (str == "false" || str == "no" || str == "off" || str == "0")
        return false;
    else
        return std::nullopt;
}

static std::optional<int> logLevelFromString(std::string_view str)
{
    if (str == "TRACE")
        return LEVEL_TRACE;
    else if (str == "INFO")
        return LEVEL_INFO;
    else if (str == "WARN")
        return LEVEL_WARN;
    else if (str == "ERROR")
        return LEVEL_ERROR;
    else if (str == "FATAL")
        return LEVEL_FATAL;
    else
        return std::nullopt;
}

static std::optional<AddressMode> addressModeFromString(std::string_view str)
{
    if (str == "NATIVE_SCION") {
        return AddressMode::NATIVE_SCION;
    } else if (str == "ADDRESS_MAPPING") {
        return AddressMode::ADDRESS_MAPPING;
    } else {
        return std::nullopt;
    }
}

static void parseAddressSurrogate(std::string_view path, const toml::table& tab,
    Options::SurrogateAddresses& addresses)
{
    using namespace scion;
    generic::IPAddress surrogate;
    scion::ScIPAddress address;

    if (auto str = tab.get_as<std::string>("surrogate"); str) {
        if (auto addr = generic::IPAddress::Parse(str->get()); addr.has_value()) {
            surrogate = *addr;
        } else {
            auto& begin = tab.source().begin;
            interposer_log(LEVEL_WARN, "%s", std::format("Invalid IP address ({}:{}:{}):",
                path, begin.line, begin.column, str->get()).c_str());
            return;
        }
    } else {
        return;
    }

    if (auto str = tab.get_as<std::string>("address"); str) {
        if (auto addr = ScIPAddress::Parse(str->get()); addr.has_value()) {
            address = *addr;
        } else {
            auto& begin = tab.source().begin;
            interposer_log(LEVEL_WARN, "%s", std::format(
                "Invalid IP address ({}:{}:{}):", path, begin.line, begin.column, str->get()).c_str());
            return;
        }
    } else {
        return;
    }

    addresses.emplace_back(std::make_pair(std::move(surrogate), std::move(address)));
}

static void parseInterposerOptions(std::string_view path, const toml::table& tab, Options& opts)
{
    if (auto str = tab.get_as<std::string>("log_level"); str) {
        if (auto level = logLevelFromString(str->get()); level) {
            opts.logLevel = *level;
        } else {
            auto& begin = tab.get("log_level")->source().begin;
            interposer_log(LEVEL_WARN, "%s", std::format(
                "Invalid log level ({}:{}:{}): {} (should be one of TRACE, INFO, WARN, ERROR, FATAL)",
                path, begin.line, begin.column, str->get()).c_str());
        }
    }
    if (auto str = tab.get_as<std::string>("address_mode"); str) {
        if (auto mode = addressModeFromString(str->get()); mode) {
            opts.addressMode = *mode;
        } else {
            auto begin = tab.get("address_mode")->source().begin;
            interposer_log(LEVEL_WARN, "%s", std::format(
                "Invalid address mode ({}:{}:{}): {} (should be NATIVE_SCION or ADDRESS_MAPPING)",
                path, begin.line, begin.column, str->get()).c_str());
        }
    }
    if (auto enable = tab.get_as<bool>("extendedAddressMapping"); enable) {
        opts.extendedAddressMapping = enable->get();
    }
    if (auto enable = tab.get_as<bool>("allowPromoteOnSendTo"); enable) {
        opts.allowPromoteOnSendTo = enable->get();
    }
    if (auto ary = tab.get_as<toml::array>("addresses"); ary) {
        for (auto&& node : *ary) {
            if (auto tab = node.as_table(); tab) {
                parseAddressSurrogate(path, *tab, opts.surrogates);
            }
        }
    }
    if (auto str = tab.get_as<std::string>("default_ipv4"); str) {
        if (auto addr = scion::generic::IPAddress::Parse(str->get()); addr && addr->is4()) {
            opts.defaultIPv4 = *addr;
        } else {
            auto begin = tab.get("default_ipv4")->source().begin;
            interposer_log(LEVEL_WARN, "%s", std::format(
                "Invalid value for default_ipv4 ({}:{}:{}): {} (must be a valid IPv4 address)",
                path, begin.line, begin.column, str->get()).c_str());
        }
    }
    if (auto str = tab.get_as<std::string>("default_ipv6"); str) {
        if (auto addr = scion::generic::IPAddress::Parse(str->get()); addr && addr->is6()) {
            opts.defaultIPv6 = *addr;
        } else {
            auto begin = tab.get("default_ipv6")->source().begin;
            interposer_log(LEVEL_WARN, "%s", std::format(
                "Invalid value for default_ipv6 ({}:{}:{}): {} (must be a valid IPv6 address)",
                path, begin.line, begin.column, str->get()).c_str());
        }
    }
    if (auto str = tab.get_as<std::string>("selector"); str) {
        opts.pathSelector = str->get();
    }
    if (auto str = tab.get_as<std::string>("selector_args"); str) {
        opts.selectorArgs = str->get();
    }
}

static void parseScionOptions(const toml::table& tab, Options& opts)
{
    if (auto daemon = tab.get_as<bool>("connect_to_daemon"); daemon) {
        opts.connectToDaemon = daemon;
    }
    if (auto str = tab.get_as<std::string>("daemon_address"); str) {
        opts.daemonAddress = str->get();
    }
}

static bool matchPattern(const std::string& executable, const std::string& pattern)
{
    return RE2::FullMatch(executable, pattern);
}

// Load options from a TOML configuration file. Only options that are present in
// the TOML and match the executable name (`opts.executable`) are updated so
// that default values remain intact.
static void loadTomlConfig(std::string_view path, Options& opts)
{
    auto res = toml::parse_file(path);
    if (res.failed()) {auto& begin = res.error().source().begin;
        interposer_log(LEVEL_WARN, "%s", std::format("Failed to load ({}:{}:{})): {}",
            path, begin.line, begin.column, res.error().description()).c_str());
        return;
    }
    auto& tbl = res.table();

    // load default section
    if (auto def = tbl.get_as<toml::table>("default"); def) {
        parseInterposerOptions(path, *def, opts);
        if (auto sc = def->get_as<toml::table>("scion"); sc)
            parseScionOptions(*def, opts);
    }

    // look for matching application-specific configuration
    if (!opts.executable.empty()) {
        for (auto&& node : tbl) {
            if (node.first != "default" && node.second.is_table()) {
                if (auto match = node.second.as_table()->get_as<std::string>("match"); match) {
                    if (matchPattern(opts.executable, match->get())) {
                        interposer_log(LEVEL_INFO, "%s", std::format(
                            "Found matching configuration section [{}]", node.first.str()).c_str());
                        auto tab = node.second.as_table();
                        parseInterposerOptions(path, *tab, opts);
                        if (auto sc = tab->get_as<toml::table>("scion"); sc)
                            parseScionOptions(*sc, opts);
                        break;
                    }
                }
            }
        }
    }
}

void loadOptions(Options& opts)
{
    // Determine host executable
    if (auto value = _getenv("SCION_ASSUME_APPLICATION"); !value.empty()) {
        opts.executable = value;
    } else {
        if (auto exe = getExecutablePath(); exe.has_value())
            opts.executable = *exe;
        else
            interposer_log(LEVEL_WARN,
                "Can't determine host executable path, applying default settings"
                " (override with SCION_ASSUME_APPLICATION)");
    }

    // Load low priority envrionment variables that may be overridden by the
    // configuration files
    if (auto value = _getenv("SCION_DAEMON_ADDRESS"); !value.empty()) {
        opts.daemonAddress = value;
    }

    // Load config files
    loadTomlConfig(DEFAULT_CONFIG_PATH, opts);
    if (auto optsPath = _getenv("SCION_CONFIG"); !optsPath.empty()) {
        loadTomlConfig(optsPath, opts);
    }

    // Load high priority environment variables that may override settings from
    // the configuration files
    if (auto value = _getenv("SCION_LOG_LEVEL"); !value.empty()) {
        if (auto level = logLevelFromString(value); level.has_value()) {
            opts.logLevel = *level;
        } else {
            interposer_log(LEVEL_WARN, "%s", std::format(
                "Invalid value for SCION_LOG_LEVEL: {}"
                " (should be NATIVE_SCION or ADDRESS_MAPPING)",
                value).c_str());
        }
    }
    if (auto value = _getenv("SCION_ADDRESS_MODE"); !value.empty()) {
        if (auto mode = addressModeFromString(value); mode.has_value()) {
            opts.addressMode = *mode;
        } else {
            interposer_log(LEVEL_WARN, "%s", std::format(
                "Invalid value for SCION_ADDRESS_MODE: {}"
                " (should be one of TRACE, INFO, WARN, ERROR, FATAL)",
                value).c_str());
        }
    }
    if (auto value = _getenv("SCION_PROMOTE_ON_SENDTO"); !value.empty()) {
        if (auto enable = parseBool(value); enable.has_value()) {
            opts.allowPromoteOnSendTo = *enable;
        } else {
            interposer_log(LEVEL_WARN, "%s", std::format(
                "Invalid value for SCION_PROMOTE_ON_SENDTO: {}"
                " (should be one of true, false)",
                value).c_str());
        }
    }
    if (auto value = _getenv("SCION_EXTENDED_ADDRESS_MAPPING"); !value.empty()) {
        if (auto enable = parseBool(value); enable.has_value()) {
            opts.extendedAddressMapping = *enable;
        } else {
            interposer_log(LEVEL_WARN, "%s", std::format(
                "Invalid value for SCION_EXTENDED_ADDRESS_MAPPING: {}"
                " (should be one of true, false)",
                value).c_str());
        }
    }
    if (auto value = _getenv("SCION_DEFAULT_IPV4"); !value.empty()) {
        if (auto addr = scion::generic::IPAddress::Parse(value); addr && addr->is4()) {
            opts.defaultIPv4 = *addr;
        } else {
            interposer_log(LEVEL_WARN, "%s", std::format(
                "Invalid value for SCION_DEFAULT_IPV4: {} (must be a valid IPv4 address)",
                value).c_str());
        }
    }
    if (auto value = _getenv("SCION_DEFAULT_IPV6"); !value.empty()) {
        if (auto addr = scion::generic::IPAddress::Parse(value); addr && addr->is4()) {
            opts.defaultIPv6 = *addr;
        } else {
            interposer_log(LEVEL_WARN, "%s", std::format(
                "Invalid value for SCION_DEFAULT_IPV6: {} (must be a valid IPv6 address)",
                value).c_str());
        }
    }
    if (auto value = _getenv("SCION_SELECTOR"); !value.empty()) {
        opts.pathSelector = value;
    }
    if (auto value = _getenv("SCION_SELECTOR_ARGS"); !value.empty()) {
        opts.selectorArgs = value;
    }
}
