// SPDX-License-Identifier: Apache-2.0
//
// Capture / MITM tap — the Wireshark/Charles analog for an emulated target.
//
// There is no real network stack to sniff; the guest's *external-interaction
// surface* is its syscalls (on Linux these ARE the network: socket/connect/
// sendto/recvfrom/read/write) plus CPU probes (cpuid/rdtsc) and port I/O. This
// tap is an Observer on the event bus that records each such interaction as a
// dissected transaction with the argument registers captured at the call site —
// the capture half. The MITM half reuses the engine's existing machinery: a
// Syscall run point bound to a mutating macro rewrites the arguments/return, and
// because those edits go through the injected-event log the modified "session"
// still replays deterministically. See docs/NETWORK_CAPTURE.md.
#pragma once

#include <array>
#include <functional>
#include <string>
#include <vector>

#include "dede/core/event.hpp"
#include "dede/macro/event_bus.hpp"

namespace dede {

enum class CapKind { Syscall, Cpuid, Rdtsc };

struct CaptureEntry {
    u64 seq = 0;
    Tick tick = 0;
    Addr pc = 0;
    CapKind kind = CapKind::Syscall;
    u64 number = 0;                 // syscall number / cpuid leaf
    std::string name;              // dissected name (e.g. "sendto")
    std::array<u64, 6> args{};     // SysV arg registers at the call
    std::string summary;          // one-line human rendering
};

// Linux x86-64 syscall name for a number (common subset incl. the network calls),
// or "sys_<n>" for the rest.
std::string syscall_name(u64 n);

class CaptureTap final : public IEventObserver {
public:
    // `regs` reads a guest register at event time (injected so this stays off the
    // session's innards). Capture is off until enabled.
    explicit CaptureTap(std::function<u64(Reg)> regs) : regs_(std::move(regs)) {}

    void set_enabled(bool on) { enabled_ = on; }
    bool enabled() const { return enabled_; }
    void clear() { entries_.clear(); seq_ = 0; }
    const std::vector<CaptureEntry>& entries() const { return entries_; }

    void on_event(const Event& e) override;

    std::string to_text() const;
    std::string to_json() const;

private:
    std::function<u64(Reg)> regs_;
    std::vector<CaptureEntry> entries_;
    u64 seq_ = 0;
    bool enabled_ = false;
};

}  // namespace dede
