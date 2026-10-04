// SPDX-License-Identifier: Apache-2.0
//
// Execution events (the message type of the Observer pattern). The core emits
// them through an IEventSink; the macro/run-point layer, the shell, and the
// decompiler subscribe. The core never knows who is listening.
#pragma once

#include <string>

#include "dede/common/types.hpp"

namespace dede {

enum class EventKind {
    Step,             // one instruction retired
    Breakpoint,       // guest executed an int3 (0xCC) itself
    MemRead,          // guest data read
    MemWrite,         // guest data write
    ExecWrittenPage,  // W^X: executing a page that was previously written
    Cpuid,            // guest executed cpuid
    Rdtsc,            // guest executed rdtsc
    Syscall,          // guest executed syscall/int
    Unsupported,      // interpreter met an instruction it does not model
    Halt,             // guest halted (hlt)
    Fault             // bad memory access, etc.
};

const char* to_string(EventKind k) noexcept;

struct Event {
    EventKind kind = EventKind::Step;
    Addr pc = 0;        // rip at the instruction that produced the event
    Addr address = 0;   // memory address / branch target, when meaningful
    u64 value = 0;      // value read/written, syscall number, cpuid leaf, ...
    unsigned size = 0;  // access size in bytes, when meaningful
    Tick tick = 0;      // retired-instruction count at the event
    std::string note;   // human detail (e.g. the unsupported mnemonic)
};

// Observer sink. The core calls emit(); subscribers live above.
class IEventSink {
public:
    virtual ~IEventSink() = default;
    virtual void emit(const Event& e) = 0;
};

// Null Object: a sink that drops everything, so the core can run without a bus
// wired up (tests, headless replay) with no null checks on the hot path.
class NullEventSink final : public IEventSink {
public:
    void emit(const Event&) override {}
};

}  // namespace dede
