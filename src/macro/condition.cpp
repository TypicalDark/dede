// SPDX-License-Identifier: Apache-2.0
#include "dede/macro/condition.hpp"

#include <sstream>

namespace dede {

std::optional<Condition> Condition::parse(const std::string& text) {
    std::istringstream is(text);
    std::string reg, op, imm;
    if (!(is >> reg >> op >> imm)) return std::nullopt;

    auto r = reg_from_name(reg);
    if (!r) return std::nullopt;

    Op o;
    if (op == "==") o = Op::Eq;
    else if (op == "!=") o = Op::Ne;
    else if (op == "<") o = Op::Lt;
    else if (op == ">") o = Op::Gt;
    else if (op == "<=") o = Op::Le;
    else if (op == ">=") o = Op::Ge;
    else return std::nullopt;

    u64 value;
    try {
        value = std::stoull(imm, nullptr, 0);
    } catch (...) {
        return std::nullopt;
    }

    Condition c;
    c.reg_ = *r;
    c.op_ = o;
    c.imm_ = value;
    c.source_ = text;
    return c;
}

bool Condition::evaluate(const IDebugController& c) const {
    u64 v = c.read_reg(reg_);
    switch (op_) {
        case Op::Eq: return v == imm_;
        case Op::Ne: return v != imm_;
        case Op::Lt: return v < imm_;
        case Op::Gt: return v > imm_;
        case Op::Le: return v <= imm_;
        case Op::Ge: return v >= imm_;
    }
    return false;
}

}  // namespace dede
