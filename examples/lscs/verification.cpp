#include "verification.hpp"

#include <tvm/contract.hpp>
#include <tvm/smart_switcher.hpp>
#include <tvm/contract_handle.hpp>
#include <tvm/default_support_functions.hpp>

using namespace tvm;
using namespace schema;

static constexpr unsigned ROOT_TIMESTAMP_DELAY = 100;

class verificator final : public smart_interface<iverificator>, public dverificator {
public:
    using root_replay_protection_t = replay_attack_protection::timestamp<ROOT_TIMESTAMP_DELAY>;

    __always_inline void constructor(bytes proof_msg_bytes) {
        proof_msg_ = proof_msg_bytes.cl_;
    }

    __always_inline bool_t verify() {
        return (__builtin_tvm_vergrth16(proof_msg_) > 0) ? bool_t(1) : bool_t(0);
    }

    // default processing of unknown messages
    __always_inline static int _fallback(cell msg, slice msg_body) {
        return 0;
    }

    // =============== Support functions ==================
    DEFAULT_SUPPORT_FUNCTIONS(iverificator, root_replay_protection_t)
};

DEFINE_JSON_ABI(iverificator, dverificator, everificator);

// ----------------------------- Main entry functions ---------------------- //
DEFAULT_MAIN_ENTRY_FUNCTIONS(verificator, iverificator, dverificator, ROOT_TIMESTAMP_DELAY)

