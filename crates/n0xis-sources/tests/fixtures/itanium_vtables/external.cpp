// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// A class whose base is defined in another image, built by `build.sh` as
// `vx-<target>` executables. `Ext`'s key function is defined nowhere here, so
// neither its vtable nor its type_info is in the image: the pointer to
// `_ZTI3Ext` inside `_ZTI5Local` links to 0, which is what a symbolic
// relocation against another library reads as in a file.
//
// What the source says:
//   Local : Ext   -- one base, which this image cannot name
//   Alone         -- no base

struct Ext {
    virtual int e() const;
};
struct Local : Ext {
    int e() const override;
};
int Local::e() const { return 1; }

struct Alone {
    virtual int a() const;
};
int Alone::a() const { return 2; }
