// SPDX-License-Identifier: Apache-2.0
//
// Windows x64 user-mode environment (Batch 9, T9.W2/T9.W3). Forges a PEB/TEB so
// anti-debug checks read "not debugged" (PEB.BeingDebugged = 0, NtGlobalFlag =
// 0), and shims a core Win32 API set — memory (VirtualAlloc/VirtualProtect),
// module (GetProcAddress/GetModuleHandle/LoadLibraryA), process
// (GetCurrentProcess), and anti-debug (IsDebuggerPresent) — reached via address
// hooks on synthetic API stubs (each stub is a bare `ret`; the hook sets the
// return value, then the ret returns to the caller). Arguments follow the Win64
// convention (RCX, RDX, R8, R9). Everything is forged in a pre-mapped arena; no
// host API is called, and the run stays deterministic + replayable.
#pragma once

#include <map>
#include <string>
#include <vector>

#include "dede/os/os_env.hpp"

namespace dede::os {

class WindowsEnvironment : public IOsEnvironment {
public:
    struct Region { Addr addr; u64 size; };

    // The arena [arena,arena+size) must be mapped RWX; teb/peb must be mapped RW.
    WindowsEnvironment(Addr arena, u64 size, Addr teb, Addr peb)
        : arena_(arena), end_(arena + size), next_(arena), teb_(teb), peb_(peb) {}

    std::string name() const override { return "windows-x64"; }
    // Not a syscall OS (Win32 is API-based); on_syscall handles the rare direct
    // Nt* syscall by number, but the main path is on_api via address hooks.
    void on_syscall(IDebugController&) override {}
    const std::vector<SyscallEvent>& log() const override { return log_; }

    // Write the forged PEB/TEB into memory and point gs at the TEB.
    void install(IDebugController& c);

    // Register an API name at a synthetic stub address (a bare `ret`), and
    // dispatch when the hook at that address fires (reads RIP to identify it).
    void register_api(const std::string& name, Addr stub);
    void on_api(IDebugController& c);  // bind to an Address run point per stub

    const std::vector<Region>& regions() const { return regions_; }
    const std::map<std::string, Addr>& api_map() const { return by_name_; }

    // --- forged GUI/windowing subsystem --------------------------------------
    // A window the guest created via CreateWindowEx (no real rendering — a forged
    // HWND so GUI programs run to completion under the sandbox, calls logged).
    struct Window { u64 hwnd; std::string title; };
    const std::vector<Window>& windows() const { return windows_; }
    // Feed a message so a GetMessage loop pops one (and returns nonzero) before
    // the queue empties and it returns 0 (WM_QUIT) to terminate deterministically.
    void post_message(u32 msg) { msg_queue_.push_back(msg); }

private:
    i64 handle(IDebugController& c, const std::string& api, const std::array<u64, 4>& a);
    std::string read_cstr(IDebugController& c, Addr p, std::size_t cap = 256) const;

    Addr arena_, end_, next_, teb_, peb_;
    std::map<Addr, std::string> by_addr_;
    std::map<std::string, Addr> by_name_;
    std::vector<Region> regions_;
    std::vector<SyscallEvent> log_;
    std::vector<Window> windows_;
    std::vector<u32> msg_queue_;
    u64 next_handle_ = 0x00010000;  // forged HWND/HMENU/HICON/... handles
};

}  // namespace dede::os
