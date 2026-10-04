// SPDX-License-Identifier: Apache-2.0
#include "dede/core/event.hpp"

namespace dede {

const char* to_string(EventKind k) noexcept {
    switch (k) {
        case EventKind::Step: return "step";
        case EventKind::Breakpoint: return "breakpoint";
        case EventKind::MemRead: return "mem-read";
        case EventKind::MemWrite: return "mem-write";
        case EventKind::ExecWrittenPage: return "exec-written-page";
        case EventKind::Cpuid: return "cpuid";
        case EventKind::Rdtsc: return "rdtsc";
        case EventKind::Syscall: return "syscall";
        case EventKind::Unsupported: return "unsupported";
        case EventKind::Halt: return "halt";
        case EventKind::Fault: return "fault";
    }
    return "?";
}

}  // namespace dede
