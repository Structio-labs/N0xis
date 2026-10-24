// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// The one function libFuzzer expects its user to supply: with it the vendored
// libFuzzer sources link into a whole program, a C++ image for the
// rule-accuracy corpus (oracle/rule-accuracy/corpus.py). What it computes does
// not matter; it exists to be linked.
#include <cstddef>
#include <cstdint>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    return size > 0 && data[0] == 'x';
}
