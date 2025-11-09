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

#include "console.h"

#if _WIN32

#include <stdio.h>

bool isKeyPressed(HANDLE hConsoleInput, WORD vKey)
{
    DWORD eventCount = 0;
    INPUT_RECORD buffer[8];
    while (true) {
        GetNumberOfConsoleInputEvents(hConsoleInput, &eventCount);
        if (eventCount == 0) break;
        DWORD recordsRead = 0;
        ReadConsoleInput(hConsoleInput, buffer, ARRAYSIZE(buffer), &recordsRead);
        for (DWORD i = 0; i < recordsRead; ++i) {
            if (buffer[i].EventType == KEY_EVENT) {
                const KEY_EVENT_RECORD* keyEvent = &buffer[i].Event.KeyEvent;
                if (keyEvent->bKeyDown && keyEvent->wVirtualKeyCode == vKey)
                    return true;
            }
        }
    }
    return false;
}

void console_printf(const char* fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
}

#else

#include <ncurses.h>

void curses_init_server(void)
{
    initscr();
    cbreak();
    noecho();
    scrollok(stdscr, TRUE);
    nodelay(stdscr, TRUE);
}

void curses_refresh_screen(void)
{
    refresh();
}

int curses_get_char(void)
{
    return getch();
}

void curses_end_server(void)
{
    endwin();
}

void console_printf(const char* fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    vw_printw(stdscr, fmt, args);
    va_end(args);
}

#endif
