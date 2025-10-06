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

#include "selector.hpp"
#include "builtin_selector.h"
#include "log.h"

#include <dlfcn.h>
#include <string.h>

#include <filesystem>


#if _WIN32
// TODO
#else
static void* loadSelectorLibrary(const std::filesystem::path& path)
{
    static const char* basePath = "/etc/scion/selectors";
    std::filesystem::path absolutePath;
    if (path.is_relative()) {
        absolutePath = (std::filesystem::path(basePath) / path).lexically_normal();
    } else {
        absolutePath = path;
    }

    // try as is first
    auto handle = dlopen(absolutePath.c_str(), RTLD_LAZY);
    if (handle) return handle;
    if (absolutePath.extension() != ".so") {
        // try appending .so
        absolutePath.concat(".so");
        handle = dlopen(absolutePath.c_str(), RTLD_LAZY);
        if (handle) return handle;
    }
    interposer_log(LEVEL_FATAL, "Failed to load path selector from %s: %s",
        absolutePath.c_str(), strerror(errno));
    return nullptr;
}

static void* loadSymbol(void* handle, const char* symbol)
{
    void* ptr = dlsym(handle, symbol);
    if (!ptr) {
        interposer_log(LEVEL_FATAL, "Can't find symbol '%s' in path selector", symbol);
    }
    return ptr;
}
#endif

static bool loadSelectorFromFile(const std::filesystem::path& path, PathSelector& selector)
{
    void* handle = loadSelectorLibrary(path);
    if (!handle) {
        return false;
    }

    selector.initialize = reinterpret_cast<scion_sel_initialize_t>(
        loadSymbol(handle, "scion_sel_initialize"));
    if (!selector.initialize) return false;

    selector.filter_paths = reinterpret_cast<scion_sel_filter_t>(
        loadSymbol(handle, "scion_sel_filter"));
    if (!selector.filter_paths) return false;

    selector.notify_created = reinterpret_cast<scion_sel_notify_created_t>(
        loadSymbol(handle, "scion_sel_notify_created"));
    if (!selector.notify_created) return false;

    selector.notify_close = reinterpret_cast<scion_sel_notify_close_t>(
        loadSymbol(handle, "scion_sel_notify_close"));
    if (!selector.notify_close) return false;

    selector.notify_bind = reinterpret_cast<scion_sel_notify_bind_t>(
        loadSymbol(handle, "scion_sel_notify_bind"));
    if (!selector.notify_bind) return false;

    selector.notify_connect = reinterpret_cast<scion_sel_notify_connect_t>(
        loadSymbol(handle, "scion_sel_notify_connect"));
    if (!selector.notify_connect) return false;

    selector.notify_received = reinterpret_cast<scion_sel_notify_received_t>(
        loadSymbol(handle, "scion_sel_notify_received"));
    if (!selector.notify_received) return false;

    selector.select_cached = reinterpret_cast<scion_sel_select_cached_t>(
        loadSymbol(handle, "scion_sel_select_cached"));
    if (!selector.select_cached) return false;

    selector.select_path = reinterpret_cast<scion_sel_select_t>(
        loadSymbol(handle, "scion_sel_select"));
    if (!selector.select_path) return false;

    return true;
}

bool initializeSelector(PathSelector& selector, const Options& opts)
{
    if (!opts.pathSelector.empty()) {
        if (!loadSelectorFromFile(opts.pathSelector, selector))
            return false;
    } else {
        // use built-in path selector
        selector.initialize = &scion_sel_initialize;
        selector.filter_paths = &scion_sel_filter;
        selector.notify_created = &scion_sel_notify_created;
        selector.notify_close = &scion_sel_notify_close;
        selector.notify_bind = &scion_sel_notify_bind;
        selector.notify_connect = &scion_sel_notify_connect;
        selector.notify_received = &scion_sel_notify_received;
        selector.select_cached = &scion_sel_select_cached;
        selector.select_path = &scion_sel_select;
    }
    selector.initialize(opts.executable.c_str(), opts.selectorArgs.c_str());
    return true;
}
