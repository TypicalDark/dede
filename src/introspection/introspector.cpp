// SPDX-License-Identifier: Apache-2.0
#include "dede/introspection/introspector.hpp"

namespace dede {
namespace {

// Stub used when LibVMI is not linked. It reports unavailable rather than
// pretending to walk OS structures it cannot see.
class StubIntrospector final : public IIntrospector {
public:
    std::string name() const override { return "none (build without LibVMI)"; }
    bool available() const override { return false; }
    Result<std::vector<ProcessInfo>> list_processes() override {
        return make_error("introspection requires a LibVMI build (-DDEDE_WITH_LIBVMI=ON)");
    }
};

}  // namespace

#ifndef DEDE_WITH_LIBVMI
std::unique_ptr<IIntrospector> make_introspector() {
    return std::make_unique<StubIntrospector>();
}
#endif

}  // namespace dede
