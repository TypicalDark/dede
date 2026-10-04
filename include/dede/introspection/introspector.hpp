// SPDX-License-Identifier: Apache-2.0
//
// OS introspection interface. The real backend is LibVMI (LGPLv3, so dynamically
// linked to keep its obligations off the rest of the code), compiled in behind
// DEDE_WITH_LIBVMI; otherwise a stub reports that introspection is unavailable.
#pragma once

#include <memory>
#include <string>
#include <vector>

#include "dede/common/status.hpp"
#include "dede/common/types.hpp"

namespace dede {

struct ProcessInfo {
    u64 pid = 0;
    std::string name;
    Addr page_table = 0;  // CR3 / DTB
};

class IIntrospector {
public:
    virtual ~IIntrospector() = default;
    virtual std::string name() const = 0;
    virtual bool available() const = 0;
    virtual Result<std::vector<ProcessInfo>> list_processes() = 0;
};

std::unique_ptr<IIntrospector> make_introspector();

}  // namespace dede
