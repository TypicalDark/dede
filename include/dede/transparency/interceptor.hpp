// SPDX-License-Identifier: Apache-2.0
//
// Chain of Responsibility: each interceptor decides whether to answer a probe or
// pass it to the next link. The chain, assembled as a TransparencyChain,
// implements the core's ITransparency interface.
#pragma once

#include <memory>
#include <string>
#include <vector>

#include "dede/core/transparency_iface.hpp"
#include "dede/transparency/forged_env.hpp"

namespace dede {

// One link in the chain. Returns true (and fills `out`) if it handled the probe.
class IInterceptor {
public:
    virtual ~IInterceptor() = default;
    virtual std::string name() const = 0;
    virtual bool handle(const ProbeRequest& req, ProbeResult& out) = 0;
};

// The assembled chain. Walks its links in order; the first to handle wins.
class TransparencyChain final : public ITransparency {
public:
    void append(std::unique_ptr<IInterceptor> link) { links_.push_back(std::move(link)); }

    ProbeResult handle(const ProbeRequest& req) override {
        ProbeResult out;
        for (auto& link : links_) {
            if (link->handle(req, out)) {
                out.handled = true;
                return out;
            }
        }
        return out;  // handled == false => core falls back to default behaviour
    }

    std::size_t size() const noexcept { return links_.size(); }

private:
    std::vector<std::unique_ptr<IInterceptor>> links_;
};

// Build the standard chain (cpuid, rdtsc, sidt, msr, io) over a forged env.
std::unique_ptr<TransparencyChain> make_transparency_chain(ForgedEnvironment env);

}  // namespace dede
