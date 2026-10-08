// SPDX-License-Identifier: Apache-2.0
//
// The pluggable OS user-mode environment (Batch 9, T9.3). An IOsEnvironment
// handles an intercepted API/syscall against the live machine via
// IDebugController — mutating registers/memory, returning a result, and
// recording a time-travel-visible behavioral event. It is bound to a Syscall
// (or address) run point so the engine stays deterministic + replayable: the
// handler's effects are ordinary injected mutations, so stepping back and
// replaying reproduce the run bit-for-bit. Concrete backends (Linux, Windows)
// are selected by the loaded image's format — the Strategy seam that turns
// dede's interpreter into a behavioral sandbox for user-mode malware.
#pragma once

#include <array>
#include <string>
#include <vector>

#include "dede/common/types.hpp"
#include "dede/macro/controller.hpp"

namespace dede::os {

// One recorded syscall/API event (the behavioral trace is a vector of these).
struct SyscallEvent {
    long nr = 0;                 // syscall number (or API ordinal)
    std::string name;            // human name ("write", "mmap", ...)
    std::array<u64, 6> args{};   // raw argument registers in ABI order
    i64 ret = 0;                 // value returned to the guest
    std::vector<u8> data;        // payload for I/O calls (e.g. the bytes written)
    Tick tick = 0;               // when it happened (for time-travel correlation)
};

class IOsEnvironment {
public:
    virtual ~IOsEnvironment() = default;
    virtual std::string name() const = 0;

    // Handle the syscall the guest is executing right now (bind to a Syscall
    // run point with pause=false). Reads the ABI argument registers, performs
    // the modeled effect, writes the result register, and records an event.
    virtual void on_syscall(IDebugController& c) = 0;

    // The behavioral trace, oldest first.
    virtual const std::vector<SyscallEvent>& log() const = 0;
};

}  // namespace dede::os
