// SPDX-License-Identifier: Apache-2.0
//
// The seam between the execution core and the transparency subsystem. The core
// turns anti-analysis probes (cpuid, rdtsc, sidt, rd/wrmsr, I/O) into a
// ProbeRequest and asks an ITransparency to answer it. The concrete
// Chain-of-Responsibility lives in the transparency library; the core only sees
// this interface, so it stays decoupled and testable with the Null Object.
#pragma once

#include "dede/common/types.hpp"

namespace dede {

struct ProbeRequest {
    enum class Kind { Cpuid, Rdtsc, Sidt, RdMsr, WrMsr, IoIn, IoOut } kind{};
    u64 leaf = 0;      // cpuid eax
    u64 subleaf = 0;   // cpuid ecx
    u64 arg = 0;       // msr index / io port / value, by kind
    Tick tick = 0;     // instruction count, so answers can be made deterministic
};

struct ProbeResult {
    bool handled = false;  // false => core falls back to raw/default behaviour
    u64 a = 0, b = 0, c = 0, d = 0;  // cpuid eax/ebx/ecx/edx, or rdtsc in a:d
};

class ITransparency {
public:
    virtual ~ITransparency() = default;
    virtual ProbeResult handle(const ProbeRequest& req) = 0;
};

// Null Object: answers nothing, so the core behaves as a bare CPU when no
// transparency layer is installed.
class NullTransparency final : public ITransparency {
public:
    ProbeResult handle(const ProbeRequest&) override { return {}; }
};

}  // namespace dede
