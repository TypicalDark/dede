// SPDX-License-Identifier: Apache-2.0
#include "dede/script/script_engine.hpp"

namespace dede {
namespace {

// Null Object engine: present but inert, so callers need no special-casing when
// Luau is not compiled in.
class NullScriptEngine final : public IScriptEngine {
public:
    std::string name() const override { return "none (build without Luau)"; }
    bool available() const override { return false; }
    Result<std::string> eval(const std::string&) override {
        return make_error("scripting requires a Luau build (-DDEDE_WITH_LUAU=ON)");
    }
    Result<void> load_function(const std::string&, const std::string&) override {
        return make_error("scripting requires a Luau build (-DDEDE_WITH_LUAU=ON)");
    }
};

}  // namespace

#ifndef DEDE_WITH_LUAU
std::unique_ptr<IScriptEngine> make_script_engine(AnalysisSession&) {
    return std::make_unique<NullScriptEngine>();
}
#endif

}  // namespace dede
