#pragma once

#include <tvm/replay_attack_protection/timestamp.hpp>

namespace tvm {
    namespace schema {

        // ===== Root Token Contract (Non-fungible) ===== //
        __interface iverificator {

            // expected offchain constructor execution
            __attribute__((internal, external, dyn_chain_parse)) void constructor() = 11;

            __attribute__((getter)) bool_t verify(bytes proof_msg_bytes) = 12;
        };

        struct dverificator { };

        struct everificator { };
    }    // namespace schema
}    // namespace tvm
