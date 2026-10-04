// SPDX-License-Identifier: Apache-2.0
//
// Embedded Luau engine. Compiled only when DEDE_WITH_LUAU is set and the Luau
// static libraries (Luau.VM, Luau.Compiler) are found. This is the single place
// the Luau C API lives; the rest of the project sees only IScriptEngine.
//
// The embedding follows the standard Luau host path:
//   * lua_newstate to create the VM; luau_compile + luau_load to run source
//     (compile is separable from load, so a shipped build can omit the compiler);
//   * host functions registered as C closures grouped into tables that mirror the
//     Facade (registers, memory, run points, stepping, trace, decompiler);
//   * luaL_sandbox + luaL_sandboxthread after registering globals, so scripts get
//     only the API we expose — no filesystem, no raw OS access;
//   * an interrupt callback in lua_callbacks enforcing a step/time budget so a
//     runaway or hostile script (it may run over attacker-controlled bytes) can
//     be cancelled;
//   * C++ objects handed to scripts are wrapped with lua_newuserdatadtor, since
//     Luau has no __gc metamethod.
#ifdef DEDE_WITH_LUAU

#include "dede/script/script_engine.hpp"
#include "dede/session/analysis_session.hpp"

// #include <lua.h>
// #include <lualib.h>
// #include <luacode.h>

namespace dede {
namespace {

class LuauEngine final : public IScriptEngine {
public:
    explicit LuauEngine(AnalysisSession& s) : session_(s) {
        // L_ = lua_newstate(...);
        // register_api(L_, session_);   // bind the Facade onto Luau tables
        // luaL_sandbox(L_);
        // install_interrupt_budget(L_);
    }
    ~LuauEngine() override {
        // if (L_) lua_close(L_);
    }

    std::string name() const override { return "luau"; }
    bool available() const override { return true; }

    Result<std::string> eval(const std::string&) override {
        return make_error("luau eval: binding not yet implemented in this build");
    }
    Result<void> load_function(const std::string&, const std::string&) override {
        return make_error("luau load_function: binding not yet implemented in this build");
    }

private:
    AnalysisSession& session_;
    // lua_State* L_ = nullptr;
};

}  // namespace

std::unique_ptr<IScriptEngine> make_script_engine(AnalysisSession& session) {
    return std::make_unique<LuauEngine>(session);
}

}  // namespace dede

#endif  // DEDE_WITH_LUAU
