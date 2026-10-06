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

// x86 segment registers (selectors) plus FS/GS bases, tracked so anti-VM checks
// that read them (`mov ax, cs`, etc.) see a plausible user-mode layout.
enum class Seg : u8 { CS, SS, DS, ES, FS, GS, Count };

class CpuState {
public:
    CpuState() {
        regs_.fill(0);
        // Typical x86-64 user-mode selectors (Linux/Windows look alike here).
        segs_[static_cast<std::size_t>(Seg::CS)] = 0x33;
        segs_[static_cast<std::size_t>(Seg::SS)] = 0x2b;
        segs_[static_cast<std::size_t>(Seg::DS)] = 0x2b;
        segs_[static_cast<std::size_t>(Seg::ES)] = 0x2b;
        segs_[static_cast<std::size_t>(Seg::FS)] = 0x53;
        segs_[static_cast<std::size_t>(Seg::GS)] = 0x2b;
    }

    u16 seg(Seg s) const noexcept { return segs_[static_cast<std::size_t>(s)]; }
    void set_seg(Seg s, u16 v) noexcept { segs_[static_cast<std::size_t>(s)] = v; }
    u64 fs_base() const noexcept { return fs_base_; }
    u64 gs_base() const noexcept { return gs_base_; }
    void set_fs_base(u64 v) noexcept { fs_base_ = v; }
    void set_gs_base(u64 v) noexcept { gs_base_ = v; }

    u64 get(Reg r) const noexcept { return regs_[idx(r)]; }
    void set(Reg r, u64 v) noexcept { regs_[idx(r)] = v; }

    // SSE/SSE2 128-bit vector registers xmm0..xmm15, as {low 64, high 64}.
    struct Xmm { u64 lo = 0, hi = 0; bool operator==(const Xmm& o) const noexcept { return lo == o.lo && hi == o.hi; } };
    Xmm get_xmm(int i) const noexcept { return (i >= 0 && i < 16) ? xmm_[i] : Xmm{}; }
    void set_xmm(int i, Xmm v) noexcept { if (i >= 0 && i < 16) xmm_[i] = v; }

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

    bool operator==(const CpuState& o) const noexcept { return regs_ == o.regs_ && xmm_ == o.xmm_; }

private:
    static constexpr std::size_t idx(Reg r) noexcept {
        return static_cast<std::size_t>(r);
    }
    std::array<u64, kNumReg> regs_{};
    std::array<Xmm, 16> xmm_{};
    std::array<u16, static_cast<std::size_t>(Seg::Count)> segs_{};
    u64 fs_base_ = 0;
    u64 gs_base_ = 0;
};

}  // namespace dede
