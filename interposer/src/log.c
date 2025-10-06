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

#include "log.h"
#include "stdarg.h"
#include "stdio.h"


static int log_level = LEVEL_TRACE;

void interposer_set_log_level(int level)
{
    log_level = level;
}

int interposer_log(int level, const char* fmt, ...)
{
    if (level < log_level) return 0;

    char message[256];
    va_list args;
    va_start(args, fmt);
    int n = vsnprintf(message, sizeof(message), fmt, args);
    va_end(args);

    if (level == LEVEL_TRACE)
        fprintf(stderr, "SCION Interposer (TRACE): %s\n", message);
    else if (level == LEVEL_INFO)
        fprintf(stderr, "SCION Interposer (INFO): %s\n", message);
    else if (level == LEVEL_WARN)
        fprintf(stderr, "SCION Interposer (WARNING): %s\n", message);
    else if (level == LEVEL_ERROR)
        fprintf(stderr, "SCION Interposer (ERROR): %s\n", message);
    else
        fprintf(stderr, "SCION Interposer (FATAL): %s\n", message);
    return n;
}
