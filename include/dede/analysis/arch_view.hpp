// SPDX-License-Identifier: Apache-2.0
//
// A built-in "architecture view": the subsystem dependency DAG annotated with the
// GoF patterns each subsystem carries, exported as graphviz DOT. This is the
// module-level analogue of the reference tool's UML studio with pattern
// detection — a self-documenting diagram the shell and GUI can show.
#pragma once

#include <string>
#include <vector>

namespace dede {

struct SubsystemInfo {
    std::string name;
    std::vector<std::string> depends_on;
    std::vector<std::string> patterns;
};

// The static architecture of dede (kept in step with the libraries in CMake).
const std::vector<SubsystemInfo>& architecture();

// Graphviz DOT of the subsystem DAG with pattern annotations.
std::string architecture_dot();

}  // namespace dede
