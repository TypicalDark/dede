// SPDX-License-Identifier: Apache-2.0
//
// A curated C prototype database + calling-convention binding (Batch 6, T6.2 /
// T6.3). Keyed by function name (libc, POSIX, and common Win32), each entry
// carries a C return type and parameter type spellings. The decompiler looks up
// a call's target symbol, binds the argument registers of the detected calling
// convention to those parameter types, and renders a typed call — the same
// mechanism IDA/Ghidra lean on for most real-world type accuracy.
#pragma once

#include <string>
#include <vector>

#include "dede/common/types.hpp"

namespace dede::sym {

struct Proto {
    std::string name;
    std::string ret;
    std::vector<std::string> params;  // C type spellings, in order; {"void"} = no args
    bool variadic = false;
};

// The prototype for `name`, or nullptr if unknown. Strips a leading '_' and a
// trailing "@N" (stdcall decoration) before lookup.
const Proto* lookup_prototype(const std::string& name);

// Number of prototypes in the database (>= 50).
std::size_t prototype_count();

// A one-line C declaration for the prototype, e.g. "size_t strlen(const char *)".
std::string declaration(const Proto& p);

// --- calling conventions ----------------------------------------------------

enum class CallConv { SysV, Win64 };

// Integer/pointer argument registers for a convention, in order.
const std::vector<Reg>& arg_registers(CallConv cc);

// Infer the convention from the set of argument registers a function reads as
// live-in: use of RDI/RSI (never argument registers under Win64) implies SysV;
// first argument in RCX with no RDI/RSI implies Win64. Defaults to SysV.
CallConv detect_callconv(const std::vector<Reg>& livein_arg_regs);

// The register that holds argument index `i` (0-based) under `cc`, or Reg::Count
// if beyond the register-argument count (then it is stack-passed).
Reg arg_register(CallConv cc, std::size_t i);

}  // namespace dede::sym
