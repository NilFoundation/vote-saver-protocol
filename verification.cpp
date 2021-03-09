#include <tvm/contract.hpp>
#include <tvm/contract_handle.hpp>
#include <tvm/default_support_functions.hpp>
#include <tvm/smart_switcher.hpp>

#include "verification.hpp"

using namespace tvm;
using namespace schema;

static constexpr unsigned ROOT_TIMESTAMP_DELAY = 100;

class RootTokenContract final : public smart_interface<IRootTokenContract>, public DRootTokenContract {
public:
    using root_replay_protection_t = replay_attack_protection::timestamp<ROOT_TIMESTAMP_DELAY>;

    __always_inline void constructor(bytes proof_msg_bytes) {
        proof_msg_ = proof_msg_bytes.cl_;
    }
    __always_inline bool_t verify() {
        return (__builtin_tvm_vergrth16(proof_msg_) > 0) ? bool_t(1) : bool_t(0);
    }
};

DEFINE_JSON_ABI(IRootTokenContract, DRootTokenContract, ERootTokenContract);

// ----------------------------- Main entry functions ---------------------- //
DEFAULT_MAIN_ENTRY_FUNCTIONS(RootTokenContract, IRootTokenContract, DRootTokenContract, ROOT_TIMESTAMP_DELAY)

