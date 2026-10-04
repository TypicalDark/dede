// SPDX-License-Identifier: Apache-2.0
//
// The scripting seam. The production engine is embedded Luau (MIT, so it links
// clean), built in behind DEDE_WITH_LUAU and sandboxed; its API is the
// AnalysisSession Facade, so a script can do anything the shell can. Without it,
// a Null Object engine reports scripting unavailable. The shell's own command
// language is a separate, always-present Interpreter (see shell/).
#pragma once

#include <memory>
#include <string>

#include "dede/common/status.hpp"

namespace dede {

class AnalysisSession;

class IScriptEngine {
public:
    virtual ~IScriptEngine() = default;
    virtual std::string name() const = 0;
    virtual bool available() const = 0;

    // Evaluate a chunk of script, returning its textual result/output.
    virtual Result<std::string> eval(const std::string& code) = 0;

    // Register a named function to be called when a run point fires (the macro
    // callback path). Returns an opaque handle usable as a Macro callback.
    virtual Result<void> load_function(const std::string& name, const std::string& body) = 0;
};

// Luau engine when compiled in, otherwise a Null Object. The session is the API
// surface the engine binds onto.
std::unique_ptr<IScriptEngine> make_script_engine(AnalysisSession& session);

}  // namespace dede
