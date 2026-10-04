// SPDX-License-Identifier: Apache-2.0
#include "dede/common/types.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <string>

namespace dede {

namespace {
constexpr std::array<std::string_view, kNumReg> kNames = {
    "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
    "r8",  "r9",  "r10", "r11", "r12", "r13", "r14", "r15",
    "rip", "rflags"};
}  // namespace

std::string_view reg_name(Reg r) noexcept {
    auto i = static_cast<std::size_t>(r);
    return i < kNames.size() ? kNames[i] : std::string_view{"?"};
}

std::optional<Reg> reg_from_name(std::string_view name) noexcept {
    std::string lower(name);
    std::transform(lower.begin(), lower.end(), lower.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    if (lower == "pc" || lower == "ip") return Reg::Rip;
    if (lower == "flags" || lower == "eflags") return Reg::Rflags;
    for (std::size_t i = 0; i < kNames.size(); ++i) {
        if (lower == kNames[i]) return static_cast<Reg>(i);
    }
    return std::nullopt;
}

}  // namespace dede
