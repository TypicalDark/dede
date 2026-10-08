// SPDX-License-Identifier: Apache-2.0
#include "dede/core/process.hpp"

#include <algorithm>

namespace dede {

ProcessTable::Process* ProcessTable::find(int pid) {
    for (auto& p : procs_)
        if (p.pid == pid) return &p;
    return nullptr;
}
const ProcessTable::Process* ProcessTable::find(int pid) const {
    for (const auto& p : procs_)
        if (p.pid == pid) return &p;
    return nullptr;
}

int ProcessTable::spawn() {
    int pid = next_pid_++;
    procs_.push_back({pid, std::make_unique<ExecutionCore>()});
    return pid;
}

int ProcessTable::fork(int parent_pid) {
    Process* parent = find(parent_pid);
    if (!parent) return -1;
    int pid = next_pid_++;
    auto child = std::make_unique<ExecutionCore>();
    child->restore(parent->core->snapshot());  // COW-clone the whole machine
    procs_.push_back({pid, std::move(child)});
    return pid;
}

ExecutionCore& ProcessTable::core(int pid) { return *find(pid)->core; }
const ExecutionCore& ProcessTable::core(int pid) const { return *find(pid)->core; }
bool ProcessTable::alive(int pid) const { return find(pid) != nullptr; }

std::vector<int> ProcessTable::pids() const {
    std::vector<int> v;
    for (const auto& p : procs_) v.push_back(p.pid);
    return v;
}

int ProcessTable::make_pipe() {
    int id = next_pipe_++;
    pipes_[id];
    return id;
}

void ProcessTable::pipe_write(int pipe_id, const std::vector<u8>& bytes) {
    auto& q = pipes_[pipe_id];
    q.insert(q.end(), bytes.begin(), bytes.end());
}

std::vector<u8> ProcessTable::pipe_read(int pipe_id, std::size_t n) {
    auto it = pipes_.find(pipe_id);
    if (it == pipes_.end()) return {};
    auto& q = it->second;
    std::size_t take = std::min(n, q.size());
    std::vector<u8> out(q.begin(), q.begin() + take);
    q.erase(q.begin(), q.begin() + take);
    return out;
}

std::size_t ProcessTable::pipe_pending(int pipe_id) const {
    auto it = pipes_.find(pipe_id);
    return it == pipes_.end() ? 0 : it->second.size();
}

}  // namespace dede
