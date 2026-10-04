// SPDX-License-Identifier: Apache-2.0
//
// The wire protocol between the permissively-licensed main binary and the
// separate GPL emulator process (emu-host). This boundary is the whole licensing
// strategy (see docs/LICENSING.md): Unicorn/QEMU are GPL, so they live in their
// own program and never link into the main binary; the two exchange these
// messages over a pipe/socket. The same boundary the architecture already draws
// with IExecutionBackend is the one the license requires.
//
// A UnicornBackend in the main binary would implement IExecutionBackend by
// serialising these requests to the child and deserialising the replies — so from
// the core's point of view it is just another Strategy.
#pragma once

#include <cstdint>
#include <vector>

#include "dede/common/types.hpp"

namespace dede::ipc {

// Protocol version, bumped on any incompatible message change.
inline constexpr u32 kVersion = 1;

enum class MsgType : u32 {
    // host -> emu
    Hello = 1,       // negotiate version
    MapMemory,       // base, size, perms
    WriteMemory,     // base, bytes
    ReadMemory,      // base, len
    SetRegs,         // full register file
    Step,            // execute N instructions
    Snapshot,        // capture emulator state, return an opaque id
    Restore,         // restore a snapshot by id
    // emu -> host
    Ok = 0x1000,
    Regs,            // full register file
    MemoryData,      // bytes
    Event,           // an execution event (mem access, cpuid, halt, ...)
    SnapshotId,      // opaque handle for a captured state
    Error
};

// Fixed-size header prefixing every message; `length` counts the payload bytes
// that follow.
struct Header {
    u32 magic = 0x44454445;  // "DEDE"
    u32 version = kVersion;
    MsgType type = MsgType::Hello;
    u32 length = 0;
};

// Payloads are length-delimited and little-endian. A production implementation
// would use a compact serialiser; these structs document the shape.
struct MapMemoryReq {
    Addr base;
    u64 size;
    u8 perms;
};

struct StepReq {
    u64 count;  // number of instructions to execute
};

struct StepResp {
    u64 executed;  // how many actually ran before stop
    u32 stop_reason;  // maps to StepOutcome::Status
};

}  // namespace dede::ipc
