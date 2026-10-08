// SPDX-License-Identifier: Apache-2.0
//
// The surface that Commands and macros act on. The session Facade implements it;
// the macro library depends only on this interface, so the dependency runs
// macro -> core and never back into session. A "mutating" operation here is one
// the Facade also logs as an injected event, so replay reproduces it.
#pragma once

#include <string>
#include <vector>

#include "dede/common/cpu_state.hpp"
#include "dede/common/status.hpp"
#include "dede/common/types.hpp"
#include "dede/core/backend.hpp"  // StepOutcome

namespace dede {

class IDebugController {
public:
    virtual ~IDebugController() = default;

    // --- observing operations (safe on every replay) -------------------------
    virtual u64 read_reg(Reg r) const = 0;
    virtual Result<u64> read_mem(Addr a, unsigned bytes) const = 0;
    virtual Result<std::vector<u8>> read_bytes(Addr a, unsigned len) const = 0;
    virtual Tick now() const = 0;
    virtual Result<std::vector<u8>> assemble(const std::string& text, Addr at) const = 0;

    // --- mutating operations (logged as injected events) ---------------------
    virtual void write_reg(Reg r, u64 v, const std::string& note = {}) = 0;
    virtual Result<void> write_bytes(Addr a, const std::vector<u8>& data,
                                     const std::string& note = {}) = 0;

    // Thread segment bases (TLS / TEB), e.g. for arch_prctl(ARCH_SET_FS). Captured
    // by the per-tick Memento snapshot, so it is restored correctly by time-travel.
    virtual void set_fs_base(u64) {}
    virtual void set_gs_base(u64) {}

    // --- control -------------------------------------------------------------
    virtual StepOutcome step() = 0;
    virtual Result<void> step_back(Tick n) = 0;
};

}  // namespace dede
