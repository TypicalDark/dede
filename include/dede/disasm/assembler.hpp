// SPDX-License-Identifier: Apache-2.0
//
// The assembler interface used for patching. The default implementation is a
// small in-tree x86-64 encoder covering the instructions the patch/macro path
// needs; an asmjit-backed adapter can be dropped in behind the same interface
// when DEDE_WITH_ASMJIT is set (asmjit is Zlib-licensed, so it links clean).
#pragma once

#include <memory>
#include <string>
#include <vector>

#include "dede/common/status.hpp"
#include "dede/common/types.hpp"

namespace dede {

class IAssembler {
public:
    virtual ~IAssembler() = default;

    // Assemble one line of textual assembly (AT&T-free, Intel-style) at the
    // given address (address matters for relative branches). Returns the encoded
    // bytes or an error describing what could not be encoded.
    virtual Result<std::vector<u8>> assemble(const std::string& text, Addr at) const = 0;

    virtual std::string backend_name() const = 0;
};

std::unique_ptr<IAssembler> make_assembler(Arch arch);

}  // namespace dede
