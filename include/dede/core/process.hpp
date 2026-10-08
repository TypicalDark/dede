// SPDX-License-Identifier: Apache-2.0
//
// Multi-process model (Batch 9, T9.7). A process is a fresh address space (its
// own ExecutionCore). `fork` COW-clones the parent's whole machine via the
// Memento, so parent and child diverge independently — a write in one is not
// seen by the other. Inter-process channels (pipes) are mediated by this table,
// so parent<->child data flow is observable (and MITM-able) on the behavioral
// trace. Deterministic by construction: no host processes are created.
//
// This complements the DeterministicScheduler (threads sharing one space): a
// process owns a space, its threads share it. Cross-process scheduling reuses
// the same recorded-schedule discipline.
#pragma once

#include <map>
#include <memory>
#include <vector>

#include "dede/core/execution_core.hpp"

namespace dede {

class ProcessTable {
public:
    // A new, empty process with its own address space; returns its pid.
    int spawn();

    // COW-clone `parent`'s whole machine (registers + memory) into a new
    // process (fork). The child's address space is independent of the parent's.
    // Returns the child pid, or -1 if the parent is unknown.
    int fork(int parent_pid);

    ExecutionCore& core(int pid);
    const ExecutionCore& core(int pid) const;
    bool alive(int pid) const;
    std::vector<int> pids() const;
    std::size_t count() const { return procs_.size(); }

    // --- mediated IPC: a pipe is a unidirectional byte channel ----------------
    int make_pipe();                                        // returns a pipe id
    void pipe_write(int pipe_id, const std::vector<u8>& bytes);
    std::vector<u8> pipe_read(int pipe_id, std::size_t n);  // drains up to n bytes
    std::size_t pipe_pending(int pipe_id) const;

private:
    struct Process { int pid; std::unique_ptr<ExecutionCore> core; };
    std::vector<Process> procs_;
    std::map<int, std::vector<u8>> pipes_;
    int next_pid_ = 1000;
    int next_pipe_ = 1;

    Process* find(int pid);
    const Process* find(int pid) const;
};

}  // namespace dede
