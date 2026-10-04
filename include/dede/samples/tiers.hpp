// SPDX-License-Identifier: Apache-2.0
//
// Tiered tutorial samples. Five flat x86-64 payloads of increasing difficulty,
// each exercising more of dede's feature set (the later tiers literally rewrite
// their own code at run time — "dynamic changing of its code"). The companion
// walkthrough is docs/TUTORIAL.md; `dede-forge` writes these to disk as tierN.bin.
//
// Each tier's `image` is loaded at 0x1000; where a tier has a second stage it is
// placed at file offset 0x1000 so it lands at guest address 0x2000.
#pragma once

#include <string>
#include <vector>

#include "dede/common/types.hpp"

namespace dede::samples {

struct Tier {
    int n = 0;
    std::string name;
    std::string teaches;     // the dede features this tier is designed to exercise
    Addr entry = 0x1000;
    Addr stage2 = 0;         // 0 if none
    std::vector<u8> image;   // loaded at 0x1000
};

// n in 1..5.
Tier make_tier(int n);
inline constexpr int kTierCount = 5;

}  // namespace dede::samples
