// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// The processor's answer to "which run does `Plugin::drive` call?" in the
// shared object built from `plugin.cpp`. `processor_run.sh` links this program
// against the committed `vp-x86_64-linux-gnu.so` itself and runs it: a `My`
// is a `Plugin` defined here, in the program, where the library cannot see it.

#include <cstdio>

struct Plugin {
    virtual int run() const;
    virtual ~Plugin();
    int drive() const;
    int x = 0;
};

struct My : Plugin {
    int run() const override { return 7; }
};

int main() {
    My m;
    Plugin p;
    std::printf("My.drive(): %d; Plugin.drive(): %d\n", m.drive(), p.drive());
}
