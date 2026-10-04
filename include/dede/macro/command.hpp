// SPDX-License-Identifier: Apache-2.0
//
// Command (GoF). Every debugger action is a Command with execute()/undo(), which
// is what makes actions uniformly recordable, replayable, and scriptable — and
// is the unit a recorded macro is built from. A Command captures whatever it
// needs at execute() time to undo itself.
#pragma once

#include <memory>
#include <string>
#include <vector>

#include "dede/macro/controller.hpp"

namespace dede {

class ICommand {
public:
    virtual ~ICommand() = default;
    virtual std::string describe() const = 0;
    virtual Result<void> execute(IDebugController& c) = 0;
    virtual Result<void> undo(IDebugController& c) = 0;
    // Mutating commands change guest state and so must be injected for replay.
    virtual bool mutating() const = 0;
    // Prototype (GoF): produce a fresh, unexecuted copy, so a recorded macro can
    // be re-instantiated and bound to several run points independently.
    virtual std::shared_ptr<ICommand> clone() const = 0;
};

using CommandPtr = std::shared_ptr<ICommand>;

// Single-step the guest.
class StepCommand final : public ICommand {
public:
    std::string describe() const override { return "step"; }
    Result<void> execute(IDebugController& c) override { c.step(); return {}; }
    Result<void> undo(IDebugController& c) override { return c.step_back(1); }
    bool mutating() const override { return false; }
    CommandPtr clone() const override { return std::make_shared<StepCommand>(); }
};

// Write a register (undo restores the previous value).
class WriteRegCommand final : public ICommand {
public:
    WriteRegCommand(Reg r, u64 v, std::string note = {})
        : reg_(r), val_(v), note_(std::move(note)) {}
    std::string describe() const override {
        return "write " + std::string(reg_name(reg_)) + " = " + std::to_string(val_);
    }
    Result<void> execute(IDebugController& c) override {
        prev_ = c.read_reg(reg_);
        c.write_reg(reg_, val_, note_);
        return {};
    }
    Result<void> undo(IDebugController& c) override {
        c.write_reg(reg_, prev_, "undo " + note_);
        return {};
    }
    bool mutating() const override { return true; }
    CommandPtr clone() const override { return std::make_shared<WriteRegCommand>(reg_, val_, note_); }

private:
    Reg reg_;
    u64 val_;
    u64 prev_ = 0;
    std::string note_;
};

// Write raw bytes to guest memory (undo restores the previous bytes).
class WriteMemCommand final : public ICommand {
public:
    WriteMemCommand(Addr a, std::vector<u8> bytes, std::string note = {})
        : addr_(a), bytes_(std::move(bytes)), note_(std::move(note)) {}
    std::string describe() const override {
        return "write " + std::to_string(bytes_.size()) + " bytes @ " + std::to_string(addr_);
    }
    Result<void> execute(IDebugController& c) override {
        auto prev = c.read_bytes(addr_, static_cast<unsigned>(bytes_.size()));
        if (!prev) return prev.error();
        prev_ = prev.value();
        return c.write_bytes(addr_, bytes_, note_);
    }
    Result<void> undo(IDebugController& c) override {
        return c.write_bytes(addr_, prev_, "undo " + note_);
    }
    bool mutating() const override { return true; }
    CommandPtr clone() const override { return std::make_shared<WriteMemCommand>(addr_, bytes_, note_); }

private:
    Addr addr_;
    std::vector<u8> bytes_;
    std::vector<u8> prev_;
    std::string note_;
};

// Assemble `text` at `addr` and patch it in (undo restores the previous bytes).
class PatchCommand final : public ICommand {
public:
    PatchCommand(Addr a, std::string text) : addr_(a), text_(std::move(text)) {}
    std::string describe() const override { return "patch @ " + std::to_string(addr_) + ": " + text_; }
    Result<void> execute(IDebugController& c) override {
        auto enc = c.assemble(text_, addr_);
        if (!enc) return enc.error();
        auto prev = c.read_bytes(addr_, static_cast<unsigned>(enc.value().size()));
        if (!prev) return prev.error();
        prev_ = prev.value();
        return c.write_bytes(addr_, enc.value(), "patch: " + text_);
    }
    Result<void> undo(IDebugController& c) override {
        return c.write_bytes(addr_, prev_, "undo patch");
    }
    bool mutating() const override { return true; }
    CommandPtr clone() const override { return std::make_shared<PatchCommand>(addr_, text_); }

private:
    Addr addr_;
    std::string text_;
    std::vector<u8> prev_;
};

// Composite (GoF): a command made of commands. A recorded macro IS a command, so
// it can be executed, undone as a unit (children undone in reverse), cloned, and
// even nested inside another composite.
class CompositeCommand final : public ICommand {
public:
    explicit CompositeCommand(std::string name = "macro") : name_(std::move(name)) {}
    void add(CommandPtr c) { children_.push_back(std::move(c)); }
    const std::vector<CommandPtr>& children() const { return children_; }

    std::string describe() const override {
        return name_ + " (" + std::to_string(children_.size()) + " commands)";
    }
    Result<void> execute(IDebugController& c) override {
        for (auto& cmd : children_) {
            if (auto r = cmd->execute(c); !r) return r;
        }
        return {};
    }
    Result<void> undo(IDebugController& c) override {
        for (auto it = children_.rbegin(); it != children_.rend(); ++it) {
            if (auto r = (*it)->undo(c); !r) return r;
        }
        return {};
    }
    bool mutating() const override {
        for (const auto& cmd : children_) {
            if (cmd->mutating()) return true;
        }
        return false;
    }
    CommandPtr clone() const override {
        auto copy = std::make_shared<CompositeCommand>(name_);
        for (const auto& cmd : children_) copy->add(cmd->clone());
        return copy;
    }

private:
    std::string name_;
    std::vector<CommandPtr> children_;
};

}  // namespace dede
