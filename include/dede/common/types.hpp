// SPDX-License-Identifier: Apache-2.0
//
// Core value types shared across every subsystem.
//
// These are deliberately plain: they carry no behaviour and depend on nothing
// but the standard library, so the layering stays a strict DAG (common sits at
// the bottom and everybody may include it).
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace dede {

using u8 = std::uint8_t;
using u16 = std::uint16_t;
using u32 = std::uint32_t;
using u64 = std::uint64_t;
using i64 = std::int64_t;

using Addr = u64;      // guest virtual address
using Tick = u64;      // retired-instruction counter (the timeline's unit)

// The architecture we currently model end-to-end. X86_64 is the primary target;
// X86 is 32-bit IA-32 (same decoder/interpreter, 32-bit stack + address
// semantics). The type system is written so that adding another is a matter of
// a new Abstract-Factory branch.
enum class Arch { X86_64, X86 };

// The sixteen x86-64 general-purpose registers, in encoding order, followed by
// the two pieces of architectural state the built-in interpreter tracks.
enum class Reg : u8 {
    Rax = 0, Rcx, Rdx, Rbx, Rsp, Rbp, Rsi, Rdi,
    R8, R9, R10, R11, R12, R13, R14, R15,
    Rip, Rflags,
    Count
};

inline constexpr std::size_t kNumGpr = 16;
inline constexpr std::size_t kNumReg = static_cast<std::size_t>(Reg::Count);

// x86 FLAGS bits we actually compute. Enough to drive cmp/test + conditional
// branches, which is all the interpreter's instruction subset needs.
namespace flags {
inline constexpr u64 CF = 1ull << 0;
inline constexpr u64 PF = 1ull << 2;
inline constexpr u64 AF = 1ull << 4;
inline constexpr u64 ZF = 1ull << 6;
inline constexpr u64 SF = 1ull << 7;
inline constexpr u64 OF = 1ull << 11;
}  // namespace flags

// Return the canonical lowercase name of a register, or "?" if out of range.
std::string_view reg_name(Reg r) noexcept;

// Parse a register name (any case) back to a Reg. Accepts the 64-bit names plus
// "pc"/"ip" as aliases for rip. Returns nullopt on an unknown name.
std::optional<Reg> reg_from_name(std::string_view name) noexcept;

}  // namespace dede
