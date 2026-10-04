// SPDX-License-Identifier: Apache-2.0
//
// Interpreter (GoF). A deliberately small expression language for conditional
// run points, e.g. "rax == 0x40" or "rcx > 5". Anything more elaborate is left
// to the embedded script engine; this covers the common register-predicate case
// without spinning up a script VM on every instruction.
#pragma once

#include <optional>
#include <string>

#include "dede/common/types.hpp"
#include "dede/macro/controller.hpp"

namespace dede {

class Condition {
public:
    enum class Op { Eq, Ne, Lt, Gt, Le, Ge };

    // Parse "<reg> <op> <imm>"; returns nullopt on a malformed expression.
    static std::optional<Condition> parse(const std::string& text);

    bool evaluate(const IDebugController& c) const;
    const std::string& source() const { return source_; }

private:
    Reg reg_ = Reg::Rax;
    Op op_ = Op::Eq;
    u64 imm_ = 0;
    std::string source_;
};

}  // namespace dede
