/* Copyright (c) 2026 Tymofii Kosovskyi
 * SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
 *
 * A minimal embedding of the Lua 5.4 library (the `lua-src` crate ships the
 * library, not the `lua`/`luac` mains), so the obfuscation instrument has a
 * larger, real multi-function C program that runs with a deterministic output:
 * a fixed script whose printed line is the behaviour check. No file or
 * environment input, so the output is a pure function of the code.
 */
#include <stdio.h>
#include "lua.h"
#include "lauxlib.h"
#include "lualib.h"

static const char *SCRIPT =
    "local s = 0\n"
    "for i = 1, 100 do s = s + i end\n"
    "local t = {}\n"
    "for i = 1, 10 do t[i] = i * i end\n"
    "local p = 0\n"
    "for _, v in ipairs(t) do p = p + v end\n"
    "print(string.format('LUA_RESULT sum=%d sq=%d len=%d', s, p, #('obfuscation')))\n";

int main(void) {
    lua_State *L = luaL_newstate();
    if (!L) { fprintf(stderr, "no state\n"); return 2; }
    luaL_openlibs(L);
    if (luaL_dostring(L, SCRIPT) != LUA_OK) {
        fprintf(stderr, "lua: %s\n", lua_tostring(L, -1));
        lua_close(L);
        return 1;
    }
    lua_close(L);
    return 0;
}
