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
        u64 req = a[1] ? a[1] : kPage;
        if (req > (end_ - next_)) return 0;                  // overflow-safe capacity check
        u64 len = round_up(req, kPage);
        if (len < req || len > (end_ - next_)) return 0;     // round_up overflow / no room -> NULL
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
        if (0x10 > (end_ - next_)) return 0;  // out of arena -> NULL
        Addr r = next_;
        next_ += 0x10;
        return static_cast<i64>(r);
    }

    // --- forged GUI / windowing (user32 / gdi32) -----------------------------
    // No real rendering; each call returns a plausible forged result and is
    // logged, so a window-creating, message-pumping program runs to completion.
    if (api == "RegisterClassExA" || api == "RegisterClassExW" ||
        api == "RegisterClassA" || api == "RegisterClassW")
        return static_cast<i64>(++next_handle_ & 0xffff);  // a nonzero ATOM
    if (api == "CreateWindowExA" || api == "CreateWindowExW" ||
        api == "CreateWindowA" || api == "CreateWindowW") {
        u64 hwnd = ++next_handle_;
        std::string title = read_cstr(c, static_cast<Addr>(a[2]));  // lpWindowName (Win64 arg 3 = R8)
        windows_.push_back({hwnd, title});
        return static_cast<i64>(hwnd);
    }
    if (api == "ShowWindow" || api == "UpdateWindow" || api == "InvalidateRect" ||
        api == "TranslateMessage" || api == "DispatchMessageA" || api == "DispatchMessageW")
        return 1;  // TRUE / handled
    if (api == "DefWindowProcA" || api == "DefWindowProcW" || api == "PostQuitMessage")
        return 0;
    if (api == "GetMessageA" || api == "GetMessageW") {
        if (!msg_queue_.empty()) { msg_queue_.erase(msg_queue_.begin()); return 1; }  // a pending message
        return 0;  // WM_QUIT -> the message loop terminates
    }
    if (api == "PeekMessageA" || api == "PeekMessageW")
        return msg_queue_.empty() ? 0 : 1;
    if (api == "MessageBoxA" || api == "MessageBoxW")
        return 1;  // IDOK — the forged "user pressed OK"
    if (api == "LoadIconA" || api == "LoadIconW" || api == "LoadCursorA" || api == "LoadCursorW" ||
        api == "GetStockObject" || api == "LoadImageA" || api == "BeginPaint" || api == "GetDC" ||
        api == "CreateSolidBrush")
        return static_cast<i64>(++next_handle_);  // a nonzero GDI/USER handle
    if (api == "EndPaint" || api == "ReleaseDC" || api == "DestroyWindow")
        return 1;

    (void)c;
    return 0;  // unknown API: logged, safe default
}

std::string WindowsEnvironment::read_cstr(IDebugController& c, Addr p, std::size_t cap) const {
    std::string s;
    if (p == 0) return s;
    for (std::size_t i = 0; i < cap; ++i) {
        auto b = c.read_mem(p + i, 1);
        if (!b || b.value() == 0) break;
        s.push_back(static_cast<char>(b.value()));
    }
    return s;
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
