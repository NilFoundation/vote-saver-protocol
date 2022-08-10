#include<vector>

void process_encrypted_input_mode_init_voter_phase(std::size_t voter_idx, std::vector<std::uint8_t> &voter_pk_out,
                                                   std::vector<std::uint8_t> &voter_sk_out);

void process_encrypted_input_mode_vote_phase(
    std::size_t tree_depth, std::size_t eid_bits, std::size_t voter_idx, std::size_t vote, const std::vector<std::uint8_t> &merkle_tree_blob,
    const std::vector<std::uint8_t> &rt_blob,
    const std::vector<std::uint8_t> &eid_blob,
    const std::vector<std::uint8_t> &sk_blob,
    const std::vector<std::uint8_t> &pk_eid_blob,
    const std::vector<std::uint8_t> &proving_key_blob,
    const std::vector<std::uint8_t> &verification_key_blob,
    std::vector<std::uint8_t> &proof_blob, std::vector<std::uint8_t> &pinput_blob, std::vector<std::uint8_t> &ct_blob,
    std::vector<std::uint8_t> &sn_blob);

bool process_encrypted_input_mode_tally_voter_phase(
    std::size_t tree_depth,
    const std::vector<std::vector<std::uint8_t> > &cts_blobs,
    const std::vector<std::uint8_t> &vk_eid_blob,
    const std::vector<std::uint8_t> &pk_crs_blob,
    const std::vector<std::uint8_t> &vk_crs_blob,
    const std::vector<std::uint8_t> &voting_res_blob,
    const std::vector<std::uint8_t> &dec_proof_blob);