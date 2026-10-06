// SPDX-License-Identifier: Apache-2.0
#include "dede/symbols/protodb.hpp"

#include <array>
#include <unordered_map>

namespace dede::sym {
namespace {

// A compact, curated prototype table. C type spellings are kept as-is for
// rendering. This is a starter set (libc/POSIX + a few Win32); it is meant to be
// extended, not to be exhaustive.
const std::vector<Proto>& table() {
    static const std::vector<Proto> t = {
        {"strlen", "size_t", {"const char *"}, false},
        {"strcmp", "int", {"const char *", "const char *"}, false},
        {"strncmp", "int", {"const char *", "const char *", "size_t"}, false},
        {"strcpy", "char *", {"char *", "const char *"}, false},
        {"strncpy", "char *", {"char *", "const char *", "size_t"}, false},
        {"strcat", "char *", {"char *", "const char *"}, false},
        {"strchr", "char *", {"const char *", "int"}, false},
        {"strrchr", "char *", {"const char *", "int"}, false},
        {"strstr", "char *", {"const char *", "const char *"}, false},
        {"strdup", "char *", {"const char *"}, false},
        {"memcpy", "void *", {"void *", "const void *", "size_t"}, false},
        {"memmove", "void *", {"void *", "const void *", "size_t"}, false},
        {"memset", "void *", {"void *", "int", "size_t"}, false},
        {"memcmp", "int", {"const void *", "const void *", "size_t"}, false},
        {"memchr", "void *", {"const void *", "int", "size_t"}, false},
        {"malloc", "void *", {"size_t"}, false},
        {"calloc", "void *", {"size_t", "size_t"}, false},
        {"realloc", "void *", {"void *", "size_t"}, false},
        {"free", "void", {"void *"}, false},
        {"printf", "int", {"const char *"}, true},
        {"fprintf", "int", {"FILE *", "const char *"}, true},
        {"sprintf", "int", {"char *", "const char *"}, true},
        {"snprintf", "int", {"char *", "size_t", "const char *"}, true},
        {"scanf", "int", {"const char *"}, true},
        {"sscanf", "int", {"const char *", "const char *"}, true},
        {"puts", "int", {"const char *"}, false},
        {"putchar", "int", {"int"}, false},
        {"getchar", "int", {"void"}, false},
        {"fopen", "FILE *", {"const char *", "const char *"}, false},
        {"fclose", "int", {"FILE *"}, false},
        {"fread", "size_t", {"void *", "size_t", "size_t", "FILE *"}, false},
        {"fwrite", "size_t", {"const void *", "size_t", "size_t", "FILE *"}, false},
        {"fseek", "int", {"FILE *", "long", "int"}, false},
        {"ftell", "long", {"FILE *"}, false},
        {"fgets", "char *", {"char *", "int", "FILE *"}, false},
        {"fputs", "int", {"const char *", "FILE *"}, false},
        {"atoi", "int", {"const char *"}, false},
        {"atol", "long", {"const char *"}, false},
        {"strtol", "long", {"const char *", "char **", "int"}, false},
        {"qsort", "void", {"void *", "size_t", "size_t", "void *"}, false},
        {"bsearch", "void *", {"const void *", "const void *", "size_t", "size_t", "void *"}, false},
        {"abort", "void", {"void"}, false},
        {"exit", "void", {"int"}, false},
        {"getenv", "char *", {"const char *"}, false},
        {"system", "int", {"const char *"}, false},
        // POSIX / syscalls
        {"open", "int", {"const char *", "int"}, true},
        {"close", "int", {"int"}, false},
        {"read", "ssize_t", {"int", "void *", "size_t"}, false},
        {"write", "ssize_t", {"int", "const void *", "size_t"}, false},
        {"lseek", "off_t", {"int", "off_t", "int"}, false},
        {"mmap", "void *", {"void *", "size_t", "int", "int", "int", "off_t"}, false},
        {"munmap", "int", {"void *", "size_t"}, false},
        {"socket", "int", {"int", "int", "int"}, false},
        {"connect", "int", {"int", "const void *", "unsigned int"}, false},
        {"send", "ssize_t", {"int", "const void *", "size_t", "int"}, false},
        {"recv", "ssize_t", {"int", "void *", "size_t", "int"}, false},
        // a few Win32
        {"VirtualAlloc", "void *", {"void *", "size_t", "unsigned int", "unsigned int"}, false},
        {"VirtualProtect", "int", {"void *", "size_t", "unsigned int", "unsigned int *"}, false},
        {"CreateFileA", "void *", {"const char *", "unsigned int", "unsigned int", "void *", "unsigned int", "unsigned int", "void *"}, false},
        {"GetProcAddress", "void *", {"void *", "const char *"}, false},
        {"LoadLibraryA", "void *", {"const char *"}, false},
        {"WriteProcessMemory", "int", {"void *", "void *", "const void *", "size_t", "size_t *"}, false},
    };
    return t;
}

std::string strip_decoration(const std::string& name) {
    std::string n = name;
    if (!n.empty() && n[0] == '_') n = n.substr(1);           // leading underscore
    auto at = n.find('@');                                    // stdcall @N
    if (at != std::string::npos) n = n.substr(0, at);
    return n;
}

}  // namespace

const Proto* lookup_prototype(const std::string& name) {
    static const std::unordered_map<std::string, const Proto*> idx = [] {
        std::unordered_map<std::string, const Proto*> m;
        for (const auto& p : table()) m[p.name] = &p;
        return m;
    }();
    auto it = idx.find(strip_decoration(name));
    return it == idx.end() ? nullptr : it->second;
}

std::size_t prototype_count() { return table().size(); }

std::string declaration(const Proto& p) {
    std::string s = p.ret + " " + p.name + "(";
    if (p.params.size() == 1 && p.params[0] == "void") s += "void";
    else
        for (std::size_t i = 0; i < p.params.size(); ++i) s += (i ? ", " : "") + p.params[i];
    if (p.variadic) s += p.params.empty() ? "..." : ", ...";
    s += ")";
    return s;
}

const std::vector<Reg>& arg_registers(CallConv cc) {
    static const std::vector<Reg> sysv = {Reg::Rdi, Reg::Rsi, Reg::Rdx, Reg::Rcx, Reg::R8, Reg::R9};
    static const std::vector<Reg> win64 = {Reg::Rcx, Reg::Rdx, Reg::R8, Reg::R9};
    return cc == CallConv::Win64 ? win64 : sysv;
}

CallConv detect_callconv(const std::vector<Reg>& livein) {
    bool uses_rdi = false, uses_rsi = false, uses_rcx = false;
    for (Reg r : livein) {
        if (r == Reg::Rdi) uses_rdi = true;
        if (r == Reg::Rsi) uses_rsi = true;
        if (r == Reg::Rcx) uses_rcx = true;
    }
    if (uses_rdi || uses_rsi) return CallConv::SysV;   // RDI/RSI are never Win64 arg regs
    if (uses_rcx) return CallConv::Win64;              // first arg in RCX, no RDI/RSI
    return CallConv::SysV;
}

Reg arg_register(CallConv cc, std::size_t i) {
    const auto& regs = arg_registers(cc);
    return i < regs.size() ? regs[i] : Reg::Count;
}

}  // namespace dede::sym
