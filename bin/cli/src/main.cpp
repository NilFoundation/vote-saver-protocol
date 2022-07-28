//---------------------------------------------------------------------------//
// Copyright (c) 2018-2022 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2022 Ilias Khairullin <ilias@nil.foundation>
// Copyright (c) 2022 Noam Y <@NoamDev>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//---------------------------------------------------------------------------//

#include "common.hpp"

namespace boost {
    void assertion_failed(char const *expr, char const *function, char const *file, long line) {
        std::cerr << "Error: in file " << file << ": in function " << function << ": on line " << line << std::endl;
        std::exit(1);
    }
    void assertion_failed_msg(char const *expr, char const *msg, char const *function, char const *file, long line) {
        std::cerr << "Error: in file " << file << ": in function " << function << ": on line " << line << std::endl
                  << std::endl;
        std::cerr << "Error message:" << std::endl << msg << std::endl;
        std::exit(1);
    }
}    // namespace boost

/*
void process_encrypted_input_mode(const boost::program_options::variables_map &vm) {
    using scalar_field_value_type = typename encrypted_input_policy::pairing_curve_type::scalar_field_type::value_type;

    BOOST_ASSERT_MSG(vm.count("tree-depth"), "Tree depth is not specified!");
    std::size_t tree_depth = vm["tree-depth"].as<std::size_t>();

    std::size_t participants_number = 1 << tree_depth;
    std::cout << "There will be " << participants_number << " participants in voting." << std::endl;

    std::cout << "Generation of voters key pairs..." << std::endl;
    auto secret_keys = generate_random_data<bool, encrypted_input_policy::secret_key_bits>(participants_number);
    std::vector<std::array<bool, encrypted_input_policy::public_key_bits>> public_keys;
    std::vector<std::vector<scalar_field_value_type>> public_keys_field;
    std::vector<std::vector<scalar_field_value_type>> secret_keys_field;
    auto j = 0;
    for (const auto &sk : secret_keys) {
        std::array<bool, encrypted_input_policy::hash_type::digest_bits> pk {};
        hash<encrypted_input_policy::merkle_hash_type>(sk, std::begin(pk));
        public_keys.emplace_back(pk);
        std::vector<scalar_field_value_type> pk_field;
        std::vector<scalar_field_value_type> sk_field;
        std::cout << "Public key of the Voter " << j << ": ";
        for (auto c : pk) {
            std::cout << int(c);
            pk_field.emplace_back(int(c));
        }
        sk_field.reserve(sk.size());
        for (auto c : sk) {
            sk_field.emplace_back(int(c));
        }
        std::cout << std::endl;
        public_keys_field.push_back(pk_field);
        secret_keys_field.push_back(sk_field);
        marshaling_policy::write_initial_phase_voter_data(
                pk, sk, j,
                vm.count("voter-public-key-output") ? vm["voter-public-key-output"].as<std::string>() : "",
                vm.count("voter-secret-key-output") ? vm["voter-secret-key-output"].as<std::string>() : "");
        ++j;
    }
    std::cout << "Voters key pairs generated." << std::endl;

    std::cout << "Merkle tree generation upon participants public keys started..." << std::endl;
    auto tree = containers::make_merkle_tree<encrypted_input_policy::merkle_hash_type, encrypted_input_policy::arity>(
            std::cbegin(public_keys), std::cend(public_keys));
    std::vector<scalar_field_value_type> rt_field = marshaling_policy::get_multi_field_element_from_bits(tree.root());

    auto public_keys_read = marshaling_policy::read_voters_public_keys(
            vm["tree-depth"].as<std::size_t>(),
            vm.count("voter-public-key-output") ? vm["voter-public-key-output"].as<std::string>() : "");
    auto tree_built_from_read = containers::make_merkle_tree<encrypted_input_policy::merkle_hash_type, encrypted_input_policy::arity>
            (std::cbegin(public_keys_read), std::cend(public_keys_read));
    std::vector<scalar_field_value_type> rt_field_from_read = marshaling_policy::get_multi_field_element_from_bits(tree_built_from_read.root());
    BOOST_ASSERT(rt_field == rt_field_from_read);
    std::cout << "Merkle tree generation finished." << std::endl;

    BOOST_ASSERT_MSG(vm.count("eid-bits"), "Eid length is not specified!");
    const std::size_t eid_size = vm["eid-bits"].as<std::size_t>();
    std::vector<bool> eid(eid_size);
    std::generate(eid.begin(), eid.end(), [&]() { return std::rand() % 2; });
    std::cout << "Voting session (eid) is: ";
    for (auto i : eid) {
        std::cout << int(i);
    }
    std::cout << std::endl;
    std::vector<scalar_field_value_type> eid_field = marshaling_policy::get_multi_field_element_from_bits(eid);

    std::cout << "Voting system administrator generates R1CS..." << std::endl;
    components::blueprint<encrypted_input_policy::field_type> bp;
    components::block_variable<encrypted_input_policy::field_type> m_block(bp, encrypted_input_policy::msg_size);

    std::size_t chunk_size = encrypted_input_policy::field_type::value_bits - 1;

    components::blueprint_variable_vector<encrypted_input_policy::field_type> eid_packed;
    std::size_t eid_packed_size = (eid.size() + (chunk_size - 1)) / chunk_size;
    eid_packed.allocate(bp, eid_packed_size);

    components::blueprint_variable_vector<encrypted_input_policy::field_type> sn_packed;
    std::size_t sn_packed_size = (encrypted_input_policy::hash_component::digest_bits + (chunk_size - 1)) / chunk_size;
    sn_packed.allocate(bp, sn_packed_size);

    components::blueprint_variable_vector<encrypted_input_policy::field_type> root_packed;
    std::size_t root_packed_size = (encrypted_input_policy::hash_component::digest_bits + (chunk_size - 1)) / chunk_size;
    root_packed.allocate(bp, root_packed_size);

    std::size_t primary_input_size = bp.num_variables();

    components::block_variable<encrypted_input_policy::field_type> eid_block(bp, eid.size());
    components::digest_variable<encrypted_input_policy::field_type> sn_digest(
            bp, encrypted_input_policy::hash_component::digest_bits);
    components::digest_variable<encrypted_input_policy::field_type> root_digest(
            bp, encrypted_input_policy::merkle_hash_component::digest_bits);

    components::multipacking_component<encrypted_input_policy::field_type> eid_packer(bp, eid_block.bits, eid_packed, chunk_size);
    components::multipacking_component<encrypted_input_policy::field_type> sn_packer(bp, sn_digest.bits, sn_packed, chunk_size);
    components::multipacking_component<encrypted_input_policy::field_type> root_packer(bp, root_digest.bits, root_packed, chunk_size);

    components::blueprint_variable_vector<encrypted_input_policy::field_type> address_bits_va;
    address_bits_va.allocate(bp, tree_depth);
    encrypted_input_policy::merkle_proof_component path_var(bp, tree_depth);
    components::block_variable<encrypted_input_policy::field_type> sk_block(bp,
                                                                            encrypted_input_policy::secret_key_bits);
    encrypted_input_policy::voting_component vote_var(
            bp, m_block, eid_block, sn_digest, root_digest, address_bits_va, path_var, sk_block,
            components::blueprint_variable<encrypted_input_policy::field_type>(0));

    eid_packer.generate_r1cs_constraints(true);
    sn_packer.generate_r1cs_constraints(true);
    root_packer.generate_r1cs_constraints(true);

    path_var.generate_r1cs_constraints();
    vote_var.generate_r1cs_constraints();
    std::cout << "R1CS generation finished." << std::endl;
    std::cout << "Constraints number in the generated R1CS: " << bp.num_constraints() << std::endl;
    std::cout << "Variables number in the generated R1CS: " << bp.num_variables() << std::endl;
    bp.set_input_sizes(primary_input_size);

    std::cout << "Administrator generates CRS..." << std::endl;
    typename encrypted_input_policy::proof_system::keypair_type gg_keypair =
            nil::crypto3::zk::generate<encrypted_input_policy::proof_system>(bp.get_constraint_system());
    std::cout << "CRS generation finished." << std::endl;

    std::cout << "Administrator generates private, public and verification keys for El-Gamal verifiable encryption "
                 "scheme..."
              << std::endl;
    random::algebraic_random_device<typename encrypted_input_policy::pairing_curve_type::scalar_field_type> d;
    std::vector<scalar_field_value_type> rnd;
    for (std::size_t i = 0; i < encrypted_input_policy::msg_size * 3 + 2; ++i) {
        rnd.emplace_back(d());
    }
    typename encrypted_input_policy::encryption_scheme_type::keypair_type keypair =
            generate_keypair<encrypted_input_policy::encryption_scheme_type,
    modes::verifiable_encryption<encrypted_input_policy::encryption_scheme_type>>(
            rnd, {gg_keypair, encrypted_input_policy::msg_size});
    std::cout << "Private, public and verification keys for El-Gamal verifiable encryption scheme generated."
              << std::endl
              << std::endl;
    std::cout << "====================================================================" << std::endl << std::endl;

    std::cout << "Administrator initial phase marshalling started..." << std::endl;

    std::vector<std::vector<bool>> hashes(tree.cbegin(), tree.cend());
    std::size_t hashes_size = hashes.size();
    std::vector<std::array<bool, encrypted_input_policy::merkle_hash_type::digest_bits>>
            hashes_array_vector(hashes_size, std::array<bool, encrypted_input_policy::merkle_hash_type::digest_bits> {});
    for(std::size_t i=0; i < hashes_size; ++i) {
        std::copy_n(hashes[i].begin(),
                    encrypted_input_policy::merkle_hash_type::digest_bits,
                    hashes_array_vector[i].begin());
    }


    marshaling_policy::write_initial_phase_admin_data(
            gg_keypair.first, gg_keypair.second, std::get<0>(keypair), std::get<1>(keypair), std::get<2>(keypair),
            eid_field, rt_field, hashes_array_vector, vm.count("r1cs-proving-key-output") ? vm["r1cs-proving-key-output"].as<std::string>() : "",
            vm.count("r1cs-verification-key-output") ? vm["r1cs-verification-key-output"].as<std::string>() : "",
            vm.count("public-key-output") ? vm["public-key-output"].as<std::string>() : "",
            vm.count("secret-key-output") ? vm["secret-key-output"].as<std::string>() : "",
            vm.count("verification-key-output") ? vm["verification-key-output"].as<std::string>() : "",
            vm.count("eid-output") ? vm["eid-output"].as<std::string>() : "",
            vm.count("rt-output") ? vm["rt-output"].as<std::string>() : "");
    std::cout << "Marshalling finished." << std::endl;

    std::vector<typename encrypted_input_policy::encryption_scheme_type::cipher_type> ct_n;

    for (std::size_t i = 0; i < participants_number; ++i) {

        std::size_t proof_idx = i;
        std::cout << "Voter with index " << proof_idx << " generates its merkle copath..." << std::endl;
        containers::merkle_proof<encrypted_input_policy::merkle_hash_type, encrypted_input_policy::arity> path(
                tree, proof_idx);
        auto tree_pk_leaf = tree[proof_idx];
        std::cout << "Copath generated." << std::endl;

        std::vector<bool> m(encrypted_input_policy::msg_size, false);
        m[std::rand() % m.size()] = true;
        std::cout << "Voter " << proof_idx << " is willing to vote with the following ballot: { ";
        for (auto m_i : m) {
            std::cout << int(m_i);
        }
        std::cout << " }" << std::endl;
        std::vector<scalar_field_value_type> m_field;
        m_field.reserve(m.size());
        for (const auto m_i : m) {
            m_field.emplace_back(std::size_t(m_i));
        }

        std::vector<bool> eid_sk;
        std::copy(std::cbegin(eid), std::cend(eid), std::back_inserter(eid_sk));
        std::copy(std::cbegin(secret_keys[proof_idx]), std::cend(secret_keys[proof_idx]), std::back_inserter(eid_sk));
        std::vector<bool> sn = hash<encrypted_input_policy::hash_type>(eid_sk);
        std::cout << "Sender has following serial number (sn) in current session: ";
        for (auto i : sn) {
            std::cout << int(i);
        }
        std::cout << std::endl;

        // BOOST_ASSERT(!bp.is_satisfied());
        path_var.generate_r1cs_witness(path, true);
        BOOST_ASSERT(!bp.is_satisfied());
        address_bits_va.fill_with_bits_of_ulong(bp, path_var.address);
        BOOST_ASSERT(!bp.is_satisfied());
        BOOST_ASSERT(address_bits_va.get_field_element_from_bits(bp) == path_var.address);
        m_block.generate_r1cs_witness(m);
        BOOST_ASSERT(!bp.is_satisfied());
        eid_block.generate_r1cs_witness(eid);
        BOOST_ASSERT(!bp.is_satisfied());
        sk_block.generate_r1cs_witness(secret_keys[proof_idx]);
        BOOST_ASSERT(!bp.is_satisfied());
        vote_var.generate_r1cs_witness(tree.root(), sn);
        BOOST_ASSERT(!bp.is_satisfied());
        eid_packer.generate_r1cs_witness_from_bits();
        BOOST_ASSERT(!bp.is_satisfied());
        root_packer.generate_r1cs_witness_from_bits();
        BOOST_ASSERT(!bp.is_satisfied());
        sn_packer.generate_r1cs_witness_from_bits();
        BOOST_ASSERT(bp.is_satisfied());

        std::cout << "Voter " << proof_idx << " generates its vote consisting of proof and cipher text..." << std::endl;
        typename encrypted_input_policy::encryption_scheme_type::cipher_type cipher_text =
                encrypt<encrypted_input_policy::encryption_scheme_type,
        modes::verifiable_encryption<encrypted_input_policy::encryption_scheme_type>>(
                m_field, {d(), std::get<0>(keypair), gg_keypair, bp.primary_input(), bp.auxiliary_input()});
        ct_n.push_back(cipher_text);
        std::cout << "Vote generated." << std::endl;

        std::cout << "Rerandomization of the cipher text and proof started..." << std::endl;
        std::vector<scalar_field_value_type> rnd_rerandomization;
        for (std::size_t i = 0; i < 3; ++i) {
            rnd_rerandomization.emplace_back(d());
        }
        typename encrypted_input_policy::encryption_scheme_type::cipher_type rerand_cipher_text =
                rerandomize<encrypted_input_policy::encryption_scheme_type>(
                        rnd_rerandomization, cipher_text.first, {std::get<0>(keypair), gg_keypair, cipher_text.second});
        std::cout << "Rerandomization finished." << std::endl;

        std::cout << "Voter " << proof_idx << " marshalling started..." << std::endl;
        std::size_t eid_offset = m.size();
        std::size_t sn_offset = eid_offset + eid_packed.size();
        std::size_t rt_offset = sn_offset + sn_packed.size();
        std::size_t rt_offset_end = rt_offset + root_packed.size();
        typename encrypted_input_policy::proof_system::primary_input_type pinput = bp.primary_input();
        BOOST_ASSERT(std::cbegin(pinput) + rt_offset_end == std::cend(pinput));
        BOOST_ASSERT((eid_field == typename encrypted_input_policy::proof_system::primary_input_type {
                std::cbegin(pinput) + eid_offset, std::cbegin(pinput) + sn_offset}));
        BOOST_ASSERT((rt_field == typename encrypted_input_policy::proof_system::primary_input_type {
                std::cbegin(pinput) + rt_offset, std::cbegin(pinput) + rt_offset_end}));
        marshaling_policy::write_data(proof_idx, vm, gg_keypair.second, std::get<0>(keypair), rerand_cipher_text.second,
                                      typename encrypted_input_policy::proof_system::primary_input_type {
                                              std::cbegin(pinput) + eid_offset, std::cend(pinput)},
                                      rerand_cipher_text.first,
                                      typename encrypted_input_policy::proof_system::primary_input_type {
                                              std::cbegin(pinput) + eid_offset, std::cbegin(pinput) + sn_offset},
                                      typename encrypted_input_policy::proof_system::primary_input_type {
                                              std::cbegin(pinput) + sn_offset, std::cbegin(pinput) + rt_offset},
                                      typename encrypted_input_policy::proof_system::primary_input_type {
                                              std::cbegin(pinput) + rt_offset, std::cbegin(pinput) + rt_offset_end});
        std::cout << "Marshalling finished." << std::endl;

        std::cout << "Sender verifies rerandomized encrypted ballot and proof..." << std::endl;
        bool enc_verification_ans = verify_encryption<encrypted_input_policy::encryption_scheme_type>(
                rerand_cipher_text.first,
                {std::get<0>(keypair), gg_keypair.second, rerand_cipher_text.second,
                 typename encrypted_input_policy::proof_system::primary_input_type {std::cbegin(pinput) + m.size(),
                                                                                    std::cend(pinput)}});
        BOOST_ASSERT(enc_verification_ans);
        std::cout << "Encryption verification of rerandomazed cipher text and proof finished." << std::endl;

        std::cout << "Administrator decrypts ballot from rerandomized cipher text and generates decryption proof..."
                  << std::endl;
        typename encrypted_input_policy::encryption_scheme_type::decipher_type decipher_rerand_text =
                decrypt<encrypted_input_policy::encryption_scheme_type,
        modes::verifiable_encryption<encrypted_input_policy::encryption_scheme_type>>(
                rerand_cipher_text.first, {std::get<1>(keypair), std::get<2>(keypair), gg_keypair});
        BOOST_ASSERT(decipher_rerand_text.first.size() == m_field.size());
        for (std::size_t i = 0; i < m_field.size(); ++i) {
            BOOST_ASSERT(decipher_rerand_text.first[i] == m_field[i]);
        }
        std::cout << "Decryption finished, decryption proof generated." << std::endl;

        std::cout << "Any voter could verify decryption using decryption proof..." << std::endl;
        bool dec_verification_ans = verify_decryption<encrypted_input_policy::encryption_scheme_type>(
                rerand_cipher_text.first, decipher_rerand_text.first,
                {std::get<2>(keypair), gg_keypair, decipher_rerand_text.second});
        BOOST_ASSERT(dec_verification_ans);
        std::cout << "Decryption verification finished." << std::endl << std::endl;
        std::cout << "====================================================================" << std::endl << std::endl;
    }

    std::cout << "Tally results phase started." << std::endl;
    std::cout << "Administrator counts final results..." << std::endl;
    auto ct_it = std::cbegin(ct_n);
    auto ct_ = ct_it->first;
    ct_it++;
    while (ct_it != std::cend(ct_n)) {
        for (std::size_t i = 0; i < std::size(ct_); ++i) {
            ct_[i] = ct_[i] + ct_it->first[i];
        }
        ct_it++;
    }
    std::cout << "Final results are ready." << std::endl;

    std::cout << "Deciphered results of voting:" << std::endl;
    typename encrypted_input_policy::encryption_scheme_type::decipher_type decipher_rerand_sum_text =
            decrypt<encrypted_input_policy::encryption_scheme_type,
    modes::verifiable_encryption<encrypted_input_policy::encryption_scheme_type>>(
            ct_, {std::get<1>(keypair), std::get<2>(keypair), gg_keypair});
    BOOST_ASSERT(decipher_rerand_sum_text.first.size() == encrypted_input_policy::msg_size);
    for (std::size_t i = 0; i < encrypted_input_policy::msg_size; ++i) {
        std::cout << decipher_rerand_sum_text.first[i].data << ", ";
    }
    std::cout << std::endl;

    std::cout << "Tally phase marshalling started..." << std::endl;
    marshaling_policy::write_tally_phase_data(vm, decipher_rerand_sum_text);
    std::cout << "Marshalling finished." << std::endl;

    std::cout << "Verification of the deciphered tally result..." << std::endl;
    bool dec_verification_ans = verify_decryption<encrypted_input_policy::encryption_scheme_type>(
            ct_, decipher_rerand_sum_text.first, {std::get<2>(keypair), gg_keypair, decipher_rerand_sum_text.second});
    BOOST_ASSERT(dec_verification_ans);
    std::cout << "Verification of the deciphered tally result succeeded." << std::endl;
}
*/

void test() {
    std::size_t tree_depth = 5;
    std::size_t eid_bits = 64;

    std::size_t num_participants = 1 << tree_depth;
    std::vector<std::vector<std::uint8_t>> pks(num_participants);
    std::vector<std::vector<std::uint8_t>> sks(num_participants);

    for(int i = 0; i < num_participants; ++i) {
        process_encrypted_input_mode_init_voter_phase(i, pks[i], sks[i]);
    }

    std::vector<std::uint8_t> r1cs_proving_key_out;
    std::vector<std::uint8_t> r1cs_verification_key_out;

    std::vector<std::uint8_t> public_key_output;
    std::vector<std::uint8_t> secret_key_output;
    std::vector<std::uint8_t> verification_key_output;
    std::vector<std::uint8_t> eid_output;
    std::vector<std::uint8_t> rt_output;
    std::vector<std::uint8_t> merkle_tree_output;

    process_encrypted_input_mode_init_admin_phase_generate_keys(
            tree_depth, eid_bits,
            r1cs_proving_key_out, r1cs_verification_key_out,
            public_key_output, secret_key_output,
            verification_key_output);

    process_encrypted_input_mode_init_admin_phase_generate_data(
            tree_depth, eid_bits, pks,
            eid_output,
            rt_output, merkle_tree_output);

    auto start = std::chrono::high_resolution_clock::now();

    std::size_t voter_idx = 0;
    std::size_t vote = 1;

    std::vector<std::uint8_t> proof_blob;
    std::vector<std::uint8_t> pinput_blob;
    std::vector<std::uint8_t> ct_blob;
    std::vector<std::uint8_t> sn_blob;

    process_encrypted_input_mode_vote_phase(
            tree_depth, eid_bits, voter_idx, vote, merkle_tree_output,
            rt_output,
            eid_output, secret_key_output,
            public_key_output,
            r1cs_proving_key_out,
            verification_key_output,
            proof_blob, pinput_blob, ct_blob,
            sn_blob);
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - start);
    std::cout << "Vote Phase Time_execution: " << duration.count() << "ms" << std::endl;

}

int main(int argc, char *argv[]) {
    test();
/*
    srand_once();
    boost::program_options::options_description desc(
            "R1CS Generic Group PreProcessing Zero-Knowledge Succinct Non-interactive ARgument of Knowledge "
            "(https://eprint.iacr.org/2016/260.pdf) CLI Proof Generator.");
    // clang-format off
    desc.add_options()
            ("help,h", "Display help message.")
            ("version,v", "Display version.")
            ("phase,p", boost::program_options::value<std::string>(),"Execute protocol phase, allowed values:\n\t - init_voter (generate and write voters public and secret keys),\n\t - init_admin (generate and write CRS and ElGamal keys),\n\t - vote (read CRS and ElGamal keys, encrypt ballot and generate proof, then write them),\n\t - vote_verify (read voters' proofs and encrypted ballots and verify them),\n\t - tally_admin (read voters' encrypted ballots, aggregate encrypted ballots, decrypt aggregated ballot and generate decryption proof and write them),\n\t - tally_voter (read ElGamal verification and public keys, encrypted ballots, decrypted aggregated ballot, decryption proof and verify them).")
            ("voter-idx,vidx", boost::program_options::value<std::size_t>()->default_value(0),"Voter index")
            ("vote", boost::program_options::value<std::size_t>()->default_value(0),"Vote")
            ("voter-public-key-output,vpko", boost::program_options::value<std::string>()->default_value("voter_public_key"),"Voter public key")
            ("voter-secret-key-output,vsko", boost::program_options::value<std::string>()->default_value("voter_secret_key"),"Voter secret key")
            ("r1cs-proof-output,rpo", boost::program_options::value<std::string>()->default_value("r1cs_proof"), "Proof output path.")
            ("r1cs-primary-input-output,rpio", boost::program_options::value<std::string>()->default_value("r1cs_primary_input"), "Primary input output path.")
            ("r1cs-proving-key-output,rpko", boost::program_options::value<std::string>()->default_value("r1cs_proving_key"), "Proving key output path.")
            ("r1cs-verification-key-output,rvko", boost::program_options::value<std::string>()->default_value("r1cs_verification_key"), "Verification output path.")
            ("r1cs-verifier-input-output,rvio", boost::program_options::value<std::string>()->default_value("r1cs_verification_input"), "Verification input output path.")
            ("public-key-output,pko", boost::program_options::value<std::string>()->default_value("pk_eid"), "Public key output path.")
            ("verification-key-output,vko", boost::program_options::value<std::string>()->default_value("vk_eid"), "Verification key output path.")
            ("secret-key-output,sko", boost::program_options::value<std::string>()->default_value("sk_eid"), "Secret key output path.")
            ("cipher-text-output,cto", boost::program_options::value<std::string>()->default_value("cipher_text"), "Cipher text output path.")
            ("decryption-proof-output,dpo", boost::program_options::value<std::string>()->default_value("decryption_proof"), "Decryption proof output path.")
            ("voting-result-output,vro", boost::program_options::value<std::string>()->default_value("voting_result"), "Voting result output path.")
            ("eid-output,eido", boost::program_options::value<std::string>()->default_value("eid"), "Session id output path.")
            ("sn-output,sno", boost::program_options::value<std::string>()->default_value("sn"), "Serial number output path.")
            ("rt-output,rto", boost::program_options::value<std::string>()->default_value("rt"), "Session id output path.")
            ("tree-depth,td", boost::program_options::value<std::size_t>()->default_value(2), "Depth of Merkle tree built upon participants' public keys.")
            ("eid-bits,eb", boost::program_options::value<std::size_t>()->default_value(64), "EID length in bits.");
    // clang-format on

    boost::program_options::variables_map vm;
    boost::program_options::store(boost::program_options::command_line_parser(argc, argv).options(desc).run(), vm);
    boost::program_options::notify(vm);

    if (vm.count("help")) {
        std::cout << desc << std::endl;
        return 0;
    }

    if (!vm.count("phase")) {
        process_encrypted_input_mode(vm);
    } else {
        if (vm["phase"].as<std::string>() == "init_voter") {
            std::vector<std::uint8_t> voter_public_key_bb;
            std::vector<std::uint8_t> voter_secret_key_bb;
            std::string voter_pk_out =
                    vm.count("voter-public-key-output") ? vm["voter-public-key-output"].as<std::string>() : "";
            std::string voter_sk_out =
                    vm.count("voter-secret-key-output") ? vm["voter-secret-key-output"].as<std::string>() : "";

            process_encrypted_input_mode_init_voter_phase(vm["voter-idx"].as<std::size_t>(), voter_public_key_bb,
                                                          voter_secret_key_bb);

            if (!voter_pk_out.empty()) {
                auto filename = voter_pk_out + std::to_string(vm["voter-idx"].as<std::size_t>()) + ".bin";
                marshaling_policy::write_obj(std::filesystem::path(filename), {voter_public_key_bb});
            }

            if (!voter_sk_out.empty()) {
                auto filename = voter_sk_out + std::to_string(vm["voter-idx"].as<std::size_t>()) + ".bin";
                marshaling_policy::write_obj(std::filesystem::path(filename), {voter_secret_key_bb});
            }

        } else if (vm["phase"].as<std::string>() == "init_admin") {
            BOOST_ASSERT_MSG(vm.count("tree-depth"), "Tree depth is not specified!");
            auto tree_depth = vm["tree-depth"].as<std::size_t>();
            std::vector<std::uint8_t> r1cs_proving_key_out;
            std::vector<std::uint8_t> r1cs_verification_key_out;
            std::vector<std::uint8_t> public_key_output;
            std::vector<std::uint8_t> secret_key_output;
            std::vector<std::uint8_t> verification_key_output;
            std::vector<std::uint8_t> eid_output;
            std::vector<std::uint8_t> rt_output;
            std::vector<std::uint8_t> merkle_tree_output;

            auto public_keys_blobs = marshaling_policy::read_voters_public_keys_blobs(
                    tree_depth, vm.count("voter-public-key-output") ? vm["voter-public-key-output"].as<std::string>() : "");

            std::size_t eid_bits = vm["eid-bits"].as<std::size_t>();
            process_encrypted_input_mode_init_admin_phase_generate_keys(
                tree_depth, eid_bits,
                r1cs_proving_key_out, r1cs_verification_key_out,
                public_key_output, secret_key_output,
                verification_key_output);


            process_encrypted_input_mode_init_admin_phase_generate_data(
                tree_depth, eid_bits, public_keys_blobs,
                eid_output,
                rt_output, merkle_tree_output);

            if (vm.count("r1cs-proving-key-output")) {
                auto filename = vm["r1cs-proving-key-output"].as<std::string>() + ".bin";
                marshaling_policy::write_obj(std::filesystem::path(filename), {r1cs_proving_key_out});
            }
            if (vm.count("r1cs-verification-key-output")) {
                auto filename = vm["r1cs-verification-key-output"].as<std::string>() + ".bin";
                marshaling_policy::write_obj(std::filesystem::path(filename), {r1cs_verification_key_out});
            }
            if (vm.count("public-key-output")) {
                auto filename = vm["public-key-output"].as<std::string>() + ".bin";
                marshaling_policy::write_obj(std::filesystem::path(filename), {public_key_output});
            }
            if (vm.count("secret-key-output")) {
                auto filename = vm["secret-key-output"].as<std::string>() + ".bin";
                marshaling_policy::write_obj(std::filesystem::path(filename), {secret_key_output});
            }
            if (vm.count("verification-key-output")) {
                auto filename = vm["verification-key-output"].as<std::string>() + ".bin";
                marshaling_policy::write_obj(std::filesystem::path(filename), {verification_key_output});
            }
            if (vm.count("eid-output")) {
                auto filename = vm["eid-output"].as<std::string>() + ".bin";
                marshaling_policy::write_obj(std::filesystem::path(filename), {eid_output});
            }
            if (vm.count("rt-output")) {
                auto filename = vm["rt-output"].as<std::string>() + ".bin";
                marshaling_policy::write_obj(std::filesystem::path(filename), {rt_output});
            }

        } else if (vm["phase"].as<std::string>() == "vote") {
            std::vector<std::uint8_t> proof_blob;
            std::vector<std::uint8_t> pinput_blob;
            std::vector<std::uint8_t> ct_blob;
            std::vector<std::uint8_t> eid_blob;
            std::vector<std::uint8_t> sn_blob;
            std::vector<std::uint8_t> rt_blob;
            std::vector<std::uint8_t> vk_crs_blob;
            std::vector<std::uint8_t> pk_eid_blob;

            auto tree_depth = vm["tree-depth"].as<std::size_t>();
            BOOST_ASSERT_MSG(vm.count("eid-bits"), "Eid length is not specified!");
            const std::size_t eid_bits = vm["eid-bits"].as<std::size_t>();
            auto vote = vm["vote"].as<std::size_t>();
            auto proof_idx = vm["voter-idx"].as<std::size_t>();
            auto public_keys = marshaling_policy::read_voters_public_keys(
                    tree_depth, vm.count("voter-public-key-output") ? vm["voter-public-key-output"].as<std::string>() : "");
            std::vector<typename marshaling_policy::scalar_field_value_type> admin_rt_field =
                    marshaling_policy::read_scalar_vector(vm["rt-output"].as<std::string>());

            auto eid_field = marshaling_policy::read_scalar_vector(vm["eid-output"].as<std::string>());
            auto sk = marshaling_policy::deserialize_bitarray<encrypted_input_policy::secret_key_bits>(marshaling_policy::read_obj(vm["voter-secret-key-output"].as<std::string>() +
                                                                                                                                   std::to_string(proof_idx) + ".bin"));
            auto pk_eid = marshaling_policy::read_pk_eid(vm);

            typename encrypted_input_policy::proof_system::keypair_type gg_keypair = {
                    marshaling_policy::read_pk_crs(vm), marshaling_policy::read_vk_crs(vm)};

            auto tree = containers::make_merkle_tree<encrypted_input_policy::merkle_hash_type, encrypted_input_policy::arity>(
                    std::cbegin(public_keys), std::cend(public_keys));

            process_encrypted_input_mode_vote_phase(tree_depth, eid_bits, proof_idx, vote, tree, admin_rt_field, eid_field, sk,
                                                    pk_eid, gg_keypair, proof_blob, pinput_blob, ct_blob, eid_blob,
                                                    sn_blob, rt_blob, vk_crs_blob, pk_eid_blob);
            if (vm.count("r1cs-proof-output")) {
                auto filename = vm["r1cs-proof-output"].as<std::string>() + std::to_string(proof_idx) + ".bin";
                marshaling_policy::write_obj(std::filesystem::path(filename), {proof_blob});
            }
            if (vm.count("r1cs-primary-input-output")) {
                auto filename = vm["r1cs-primary-input-output"].as<std::string>() + std::to_string(proof_idx) + ".bin";
                marshaling_policy::write_obj(std::filesystem::path(filename), {pinput_blob});
            }
            if (vm.count("cipher-text-output")) {
                auto filename = vm["cipher-text-output"].as<std::string>() + std::to_string(proof_idx) + ".bin";
                marshaling_policy::write_obj(std::filesystem::path(filename), {ct_blob});
            }
            if (vm.count("sn-output")) {
                auto filename = vm["sn-output"].as<std::string>() + std::to_string(proof_idx) + ".bin";
                marshaling_policy::write_obj(std::filesystem::path(filename), {sn_blob});
            }
            if (vm.count("r1cs-verifier-input-output")) {
                auto filename = vm["r1cs-verifier-input-output"].as<std::string>() + std::to_string(proof_idx) + ".bin";
                auto filename1 = vm["r1cs-verifier-input-output"].as<std::string>() + std::string("_chunked") +
                                 std::to_string(proof_idx) + ".bin";
                marshaling_policy::write_obj(std::filesystem::path(filename),
                                             {proof_blob, vk_crs_blob, pk_eid_blob, ct_blob, pinput_blob});
                marshaling_policy::write_obj(
                        std::filesystem::path(filename1),
                        {proof_blob, vk_crs_blob, pk_eid_blob, ct_blob, eid_blob, sn_blob, rt_blob});
            }

        } else if (vm["phase"].as<std::string>() == "tally_admin") {
            auto tree_depth = vm["tree-depth"].as<std::size_t>();
            auto sk_eid = marshaling_policy::read_sk_eid(vm);
            auto vk_eid = marshaling_policy::read_vk_eid(vm);
            typename encrypted_input_policy::proof_system::keypair_type gg_keypair = {
                    marshaling_policy::read_pk_crs(vm), marshaling_policy::read_vk_crs(vm)};
            std::size_t participants_number = 1 << tree_depth;
            std::vector<typename encrypted_input_policy::encryption_scheme_type::cipher_type::first_type> cts;
            cts.reserve(participants_number);
            for (auto proof_idx = 0; proof_idx < participants_number; proof_idx++) {
                cts[proof_idx] = marshaling_policy::read_ct(vm, proof_idx);
            }

            std::vector<std::uint8_t> dec_proof_blob;
            std::vector<std::uint8_t> voting_res_blob;

            process_encrypted_input_mode_tally_admin_phase(tree_depth, cts, sk_eid, vk_eid, gg_keypair, dec_proof_blob,
                                                           voting_res_blob);

            if (vm.count("decryption-proof-output")) {
                auto filename = vm["decryption-proof-output"].as<std::string>() + ".bin";
                marshaling_policy::write_obj(filename, {
                        dec_proof_blob,
                });
            }

            if (vm.count("voting-result-output")) {
                auto filename = vm["voting-result-output"].as<std::string>() + ".bin";
                marshaling_policy::write_obj(filename, {
                        voting_res_blob,
                });
            }
        } else if (vm["phase"].as<std::string>() == "tally_voter") {
            BOOST_ASSERT_MSG(vm.count("tree-depth"), "Tree depth is not specified!");
            auto tree_depth = vm["tree-depth"].as<std::size_t>();
            auto vk_eid = marshaling_policy::read_vk_eid(vm);
            typename encrypted_input_policy::proof_system::keypair_type gg_keypair = {
                    marshaling_policy::read_pk_crs(vm), marshaling_policy::read_vk_crs(vm)};
            std::size_t participants_number = 1 << tree_depth;
            std::vector<typename encrypted_input_policy::encryption_scheme_type::cipher_type::first_type> cts;
            cts.reserve(participants_number);
            for (auto proof_idx = 0; proof_idx < participants_number; proof_idx++) {
                cts[proof_idx] = marshaling_policy::read_ct(vm, proof_idx);
            }

            auto voting_result = marshaling_policy::read_scalar_vector(vm["voting-result-output"].as<std::string>());
            auto dec_proof = marshaling_policy::read_decryption_proof(vm);

            process_encrypted_input_mode_tally_voter_phase(tree_depth, cts, vk_eid, gg_keypair, voting_result,
                                                           dec_proof);
        } else if (vm["phase"].as<std::string>() == "test"){
            test();
        } else {
            std::cout << desc << std::endl;
            return 0;
        }
    }
*/
    return 0;
}