// SPDX-License-Identifier: Apache-2.0
//
// C++ symbol demangling (Batch 6, T6.3). A self-contained recursive-descent
// Itanium ABI demangler (the GCC/Clang/ELF scheme) covering the common cases —
// nested names, constructors/destructors, builtin and pointer/ref/const types,
// function parameter lists, `std::` abbreviations, operators, and a light subset
// of templates and substitutions — plus a minimal MSVC (`?name@scope@@...`)
// decoder. Anything it cannot parse is returned unchanged, so it is always safe
// to run over a raw symbol name.
#pragma once

#include <string>

namespace dede::sym {

// Demangle an Itanium-mangled name ("_Z..."). Returns the readable form, or the
// input unchanged if it is not a parseable Itanium name.
std::string demangle_itanium(const std::string& mangled);

// Demangle a minimal subset of MSVC names ("?name@scope@@..."): returns the
// scope-qualified name, or the input unchanged.
std::string demangle_msvc(const std::string& mangled);

// Dispatch on the prefix: "_Z" -> Itanium, "?" -> MSVC, else unchanged.
std::string demangle(const std::string& mangled);

}  // namespace dede::sym
