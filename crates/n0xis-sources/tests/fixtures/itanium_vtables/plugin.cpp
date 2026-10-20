// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// A class whose hierarchy is all here: nothing in this file derives from
// `Plugin`, and `drive` calls `run` through `this`. Built as a shared object,
// the program that loads it may derive from `Plugin` all the same
// (`plugin_run.cpp`, which does); built as a program, nothing does.

struct Plugin {
    virtual int run() const;
    virtual ~Plugin();
    int drive() const;
    int x = 0;
};

int Plugin::run() const { return 1; }
Plugin::~Plugin() {}

__attribute__((noinline)) int Plugin::drive() const { return run() + 1000; }

// A second root class, after `Plugin`, so that `Plugin`'s table is not the
// image's last: a slot in the last table has no bound and is refused.
struct Codec {
    virtual int code() const;
    virtual ~Codec();
};

int Codec::code() const { return 2; }
Codec::~Codec() {}
