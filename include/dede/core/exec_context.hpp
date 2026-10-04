// SPDX-License-Identifier: Apache-2.0
#pragma once

#include "dede/common/types.hpp"

namespace dede {

// The "where are we" shared between the core, the memory proxy, and the backend
// for the duration of a single step, so events can be tagged with pc/tick
// without threading those through every call.
struct ExecContext {
    Addr pc = 0;
    Tick tick = 0;
};

}  // namespace dede
