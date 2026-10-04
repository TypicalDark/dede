// SPDX-License-Identifier: Apache-2.0
//
// The architectural register file for x86-64, with width-aware access so the
// interpreter can read/write al/ax/eax/rax and friends with correct x86
// semantics (32-bit writes zero-extend; 8/16-bit writes preserve the upper
// bits).
#pragma once

#include <array>

#include "dede/common/types.hpp"

namespace dede {

// Sub-register width for a GPR access.
enum class Width : u8 { B1 = 1, B2 = 2, B4 = 4, B8 = 8 };

class CpuState {
public:
    CpuState() { regs_.fill(0); }

    u64 get(Reg r) const noexcept { return regs_[idx(r)]; }
    void set(Reg r, u64 v) noexcept { regs_[idx(r)] = v; }

    u64 rip() const noexcept { return regs_[idx(Reg::Rip)]; }
    void set_rip(u64 v) noexcept { regs_[idx(Reg::Rip)] = v; }

    u64 rflags() const noexcept { return regs_[idx(Reg::Rflags)]; }
    void set_rflags(u64 v) noexcept { regs_[idx(Reg::Rflags)] = v; }

    bool flag(u64 mask) const noexcept { return (rflags() & mask) != 0; }
    void set_flag(u64 mask, bool on) noexcept {
        u64 f = rflags();
        f = on ? (f | mask) : (f & ~mask);
        set_rflags(f);
    }

    // Width-aware read of a GPR's low bytes.
    u64 read(Reg r, Width w) const noexcept {
        u64 full = regs_[idx(r)];
        switch (w) {
            case Width::B1: return full & 0xffull;
            case Width::B2: return full & 0xffffull;
            case Width::B4: return full & 0xffff'ffffull;
            case Width::B8: return full;
        }
        return full;
    }

    // Width-aware write obeying x86 partial-register rules.
    void write(Reg r, Width w, u64 v) noexcept {
        u64& full = regs_[idx(r)];
        switch (w) {
            case Width::B1: full = (full & ~0xffull) | (v & 0xffull); break;
            case Width::B2: full = (full & ~0xffffull) | (v & 0xffffull); break;
            case Width::B4: full = (v & 0xffff'ffffull); break;  // zero-extends
            case Width::B8: full = v; break;
        }
    }

    const std::array<u64, kNumReg>& raw() const noexcept { return regs_; }
    std::array<u64, kNumReg>& raw() noexcept { return regs_; }

    bool operator==(const CpuState& o) const noexcept { return regs_ == o.regs_; }

private:
    static constexpr std::size_t idx(Reg r) noexcept {
        return static_cast<std::size_t>(r);
    }
    std::array<u64, kNumReg> regs_{};
};

}  // namespace dede
