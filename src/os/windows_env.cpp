// SPDX-License-Identifier: Apache-2.0
#include "dede/os/windows_env.hpp"

namespace dede::os {
namespace {
constexpr u64 kPage = 0x1000;
u64 round_up(u64 v, u64 a) { return (v + a - 1) & ~(a - 1); }
std::vector<u8> le64(u64 v) {
    std::vector<u8> b(8);
    for (int i = 0; i < 8; ++i) b[i] = static_cast<u8>(v >> (8 * i));
    return b;
}
}  // namespace

void WindowsEnvironment::install(IDebugController& c) {
    // TEB (gs base): NtTib.Self at +0x30, ProcessEnvironmentBlock at +0x60.
    c.write_bytes(teb_ + 0x30, le64(teb_), "TEB.Self");
    c.write_bytes(teb_ + 0x60, le64(peb_), "TEB.PEB");
    // PEB: BeingDebugged (byte @ +0x02) = 0, NtGlobalFlag (dword @ +0xBC) = 0.
    c.write_bytes(peb_ + 0x02, {0x00}, "PEB.BeingDebugged");
    c.write_bytes(peb_ + 0xBC, {0x00, 0x00, 0x00, 0x00}, "PEB.NtGlobalFlag");
    c.set_gs_base(teb_);
}

void WindowsEnvironment::register_api(const std::string& name, Addr stub) {
    by_addr_[stub] = name;
    by_name_[name] = stub;
}

i64 WindowsEnvironment::handle(IDebugController& c, const std::string& api,
                               const std::array<u64, 4>& a) {
    if (api == "VirtualAlloc") {  // (lpAddress, dwSize, flAllocationType, flProtect)
        u64 len = round_up(a[1] ? a[1] : kPage, kPage);
        if (next_ + len > end_) return 0;  // NULL on failure
        Addr r = next_;
        next_ += len;
        regions_.push_back({r, len});
        return static_cast<i64>(r);
    }
    if (api == "VirtualProtect") return 1;                 // TRUE
    if (api == "IsDebuggerPresent") return 0;              // never debugged
    if (api == "GetCurrentProcess") return static_cast<i64>(~0ull);  // pseudo-handle -1
    if (api == "GetCurrentProcessId") return 4242;
    if (api == "GetModuleHandleA" || api == "GetModuleHandleW" || api == "LoadLibraryA")
        return static_cast<i64>(0x180000000ull);           // a plausible module base
    if (api == "GetProcAddress") {
        // return a fresh synthetic stub for the requested proc (next_ bump)
        Addr r = next_;
        next_ += 0x10;
        return static_cast<i64>(r);
    }
    (void)c;
    return 0;  // unknown API: logged, safe default
}

void WindowsEnvironment::on_api(IDebugController& c) {
    Addr rip = static_cast<Addr>(c.read_reg(Reg::Rip));
    auto it = by_addr_.find(rip);
    if (it == by_addr_.end()) return;  // not one of ours
    std::array<u64, 4> a = {c.read_reg(Reg::Rcx), c.read_reg(Reg::Rdx),
                            c.read_reg(Reg::R8), c.read_reg(Reg::R9)};
    i64 ret = handle(c, it->second, a);
    c.write_reg(Reg::Rax, static_cast<u64>(ret), std::string("win32 ") + it->second);
    log_.push_back({0, it->second, {a[0], a[1], a[2], a[3], 0, 0}, ret, {}, c.now()});
}

}  // namespace dede::os
