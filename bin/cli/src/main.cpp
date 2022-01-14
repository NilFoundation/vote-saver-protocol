//---------------------------------------------------------------------------//
// Copyright (c) 2018-2021 Mikhail Komarov <nemo@nil.foundation>
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

#include <iostream>
#include <filesystem>
#include <fstream>
#include <string>
#include <functional>

#include <boost/filesystem.hpp>
#include <boost/program_options.hpp>
#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

#include "detail/r1cs_examples.hpp"
#include "detail/sha256_component.hpp"
#include <nil/crypto3/zk/components/voting/encrypted_input_voting.hpp>

#include <nil/crypto3/algebra/curves/bls12.hpp>
#include <nil/crypto3/algebra/fields/bls12/base_field.hpp>
#include <nil/crypto3/algebra/fields/bls12/scalar_field.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/bls12.hpp>
#include <nil/crypto3/algebra/curves/params/multiexp/bls12.hpp>
#include <nil/crypto3/algebra/curves/params/wnaf/bls12.hpp>
#include <nil/crypto3/algebra/pairing/bls12.hpp>
#include <nil/crypto3/algebra/pairing/mnt4.hpp>
#include <nil/crypto3/algebra/pairing/mnt6.hpp>

#include <nil/crypto3/zk/components/blueprint.hpp>
#include <nil/crypto3/zk/components/blueprint_variable.hpp>
#include <nil/crypto3/zk/components/disjunction.hpp>

#include <nil/crypto3/zk/snark/systems/ppzksnark/r1cs_gg_ppzksnark.hpp>
#include <nil/crypto3/zk/snark/systems/ppzksnark/r1cs_gg_ppzksnark/marshalling.hpp>

#include <nil/crypto3/zk/snark/algorithms/generate.hpp>
#include <nil/crypto3/zk/snark/algorithms/verify.hpp>
#include <nil/crypto3/zk/snark/algorithms/prove.hpp>

#include <nil/marshalling/status_type.hpp>
#include <nil/crypto3/marshalling/zk/types/r1cs_gg_ppzksnark/primary_input.hpp>
#include <nil/crypto3/marshalling/zk/types/r1cs_gg_ppzksnark/proof.hpp>
#include <nil/crypto3/marshalling/zk/types/r1cs_gg_ppzksnark/verification_key.hpp>

#include <nil/crypto3/pubkey/algorithm/generate_keypair.hpp>
#include <nil/crypto3/pubkey/algorithm/encrypt.hpp>
#include <nil/crypto3/pubkey/algorithm/decrypt.hpp>
#include <nil/crypto3/pubkey/algorithm/verify_encryption.hpp>
#include <nil/crypto3/pubkey/algorithm/verify_decryption.hpp>
#include <nil/crypto3/pubkey/algorithm/rerandomize.hpp>
#include <nil/crypto3/pubkey/elgamal_verifiable.hpp>
#include <nil/crypto3/pubkey/modes/verifiable_encryption.hpp>

#include <nil/crypto3/random/algebraic_random_device.hpp>

using namespace nil::crypto3;
using namespace nil::crypto3::algebra;
using namespace nil::crypto3::pubkey;
using namespace nil::crypto3::marshalling;
using namespace nil::crypto3::zk;

template<typename FieldType>
components::blueprint<FieldType> test_disjunction_component(size_t w) {

    using field_type = FieldType;

    std::size_t n = std::log2(w) + ((w > (1ul << std::size_t(std::log2(w)))) ? 1 : 0);

    components::blueprint<field_type> bp;
    components::blueprint_variable<field_type> output;
    output.allocate(bp);

    bp.set_input_sizes(1);

    components::blueprint_variable_vector<field_type> inputs;
    inputs.allocate(bp, n);

    components::disjunction<field_type> d(bp, inputs, output);
    d.generate_r1cs_constraints();

    for (std::size_t j = 0; j < n; ++j) {
        bp.val(inputs[j]) = typename field_type::value_type((w & (1ul << j)) ? 1 : 0);
    }

    d.generate_r1cs_witness();

    BOOST_ASSERT(bp.val(output) == (w ? field_type::value_type::one() : field_type::value_type::zero()));
    BOOST_ASSERT(bp.is_satisfied());

    return bp;
}

template<typename Curve, typename Endianness, typename ProofSystem>
void process_basic_mode(const boost::program_options::variables_map &vm) {
    using curve_type = Curve;
    using endianness = Endianness;
    using proof_system_type = ProofSystem;
    using scalar_field_type = typename curve_type::scalar_field_type;

    using unit_type = unsigned char;
    using verification_key_marshalling_type =
        types::r1cs_gg_ppzksnark_verification_key<nil::marshalling::field_type<endianness>,
                                                  typename proof_system_type::verification_key_type>;
    using proof_marshalling_type = types::r1cs_gg_ppzksnark_proof<nil::marshalling::field_type<endianness>,
                                                                  typename proof_system_type::proof_type>;
    using primary_input_marshalling_type =
        types::r1cs_gg_ppzksnark_primary_input<nil::marshalling::field_type<endianness>,
                                               typename proof_system_type::primary_input_type>;

    std::cout << "Blueprint generation started..." << std::endl;
    std::cout << "R1CS generation started..." << std::endl;
    components::blueprint<scalar_field_type> bp = sha2_two_to_one_bp<scalar_field_type>();
    std::cout << "R1CS generation finished." << std::endl;
    std::cout << "Blueprint generation finished." << std::endl;

    std::cout << "Keys generation started..." << std::endl;
    const typename proof_system_type::keypair_type keypair =
        zk::snark::generate<proof_system_type>(bp.get_constraint_system());
    std::cout << "Keys generation finished." << std::endl;

    std::cout << "Proving started..." << std::endl;
    const typename proof_system_type::proof_type proof =
        zk::snark::prove<proof_system_type>(keypair.first, bp.primary_input(), bp.auxiliary_input());
    std::cout << "Proving finished." << std::endl;

    std::cout << "Marshalling started..." << std::endl;
    verification_key_marshalling_type filled_verification_key_val =
        types::fill_r1cs_gg_ppzksnark_verification_key<typename proof_system_type::verification_key_type, endianness>(
            keypair.second);

    proof_marshalling_type filled_proof_val =
        types::fill_r1cs_gg_ppzksnark_proof<typename proof_system_type::proof_type, endianness>(proof);

    primary_input_marshalling_type filled_primary_input_val =
        types::fill_r1cs_gg_ppzksnark_primary_input<typename proof_system_type::primary_input_type, endianness>(
            bp.primary_input());

    std::cout << "Marshalling finished." << std::endl;

    std::vector<unit_type> verification_key_byteblob;
    verification_key_byteblob.resize(filled_verification_key_val.length(), 0x00);
    auto write_iter = verification_key_byteblob.begin();

    typename nil::marshalling::status_type status =
        filled_verification_key_val.write(write_iter, verification_key_byteblob.size());

    std::vector<unit_type> proof_byteblob;
    proof_byteblob.resize(filled_proof_val.length(), 0x00);
    write_iter = proof_byteblob.begin();

    status = filled_proof_val.write(write_iter, proof_byteblob.size());

    std::vector<unit_type> primary_input_byteblob;

    primary_input_byteblob.resize(filled_primary_input_val.length(), 0x00);
    auto primary_input_write_iter = primary_input_byteblob.begin();

    status = filled_primary_input_val.write(primary_input_write_iter, primary_input_byteblob.size());

    std::cout << "Byteblobs filled." << std::endl;

    if (vm.count("verifying-key-output")) {
        std::ofstream out(vm["verifying-key-output"].as<std::filesystem::path>(), std::ios_base::binary);
        for (const auto &v : verification_key_byteblob) {
            out << v;
        }
        out.close();
    }

    if (vm.count("proof-output")) {
        std::ofstream out(vm["proof-output"].as<std::filesystem::path>(), std::ios_base::binary);
        for (const auto &v : proof_byteblob) {
            out << v;
        }
        out.close();
    }

    if (vm.count("primary-input-output")) {
        std::ofstream out(vm["primary-input-output"].as<std::filesystem::path>(), std::ios_base::binary);
        for (const auto &v : primary_input_byteblob) {
            out << v;
        }
        out.close();
    }

    // nil::marshalling::status_type provingProcessingStatus = nil::marshalling::status_type::success;
    // typename proof_system_type::proving_key_type other =
    //             nil::marshalling::verifier_input_deserializer_tvm<proof_system_type>::proving_key_process(
    //                 proving_key_byteblob.cbegin(),
    //                 proving_key_byteblob.cend(),
    //                 provingProcessingStatus);

    // BOOST_ASSERT(keypair.first == other);

    if (vm.count("verifier-input-output")) {
        std::vector<std::uint8_t> verifier_input_output_byteblob(proof_byteblob.begin(), proof_byteblob.end());

        verifier_input_output_byteblob.insert(verifier_input_output_byteblob.end(), primary_input_byteblob.begin(),
                                              primary_input_byteblob.end());
        verifier_input_output_byteblob.insert(verifier_input_output_byteblob.end(), verification_key_byteblob.begin(),
                                              verification_key_byteblob.end());

        std::ofstream poutf(vm["verifier-input-output"].as<std::filesystem::path>(), std::ios_base::binary);
        for (const auto &v : verifier_input_output_byteblob) {
            poutf << v;
        }
        poutf.close();
    }
}

template<typename ProofSystem, typename PublicKey, typename CipherText>
struct marshaling_verification_data_groth16_encrypted_input {
    using proof_type = typename ProofSystem::proof_type;
    using verification_key_type = typename ProofSystem::verification_key_type;
    using primary_input_type = typename ProofSystem::primary_input_type;

    using endianness = nil::marshalling::option::big_endian;
    using proof_marshaling_type =
        nil::crypto3::marshalling::types::r1cs_gg_ppzksnark_proof<nil::marshalling::field_type<endianness>, proof_type>;
    using verification_key_marshaling_type =
        nil::crypto3::marshalling::types::r1cs_gg_ppzksnark_extended_verification_key<
            nil::marshalling::field_type<endianness>, verification_key_type>;
    using public_key_marshaling_type =
        nil::crypto3::marshalling::types::elgamal_verifiable_public_key<nil::marshalling::field_type<endianness>,
                                                                        PublicKey>;
    using ct_marshaling_type = nil::crypto3::marshalling::types::r1cs_gg_ppzksnark_encrypted_primary_input<
        nil::marshalling::field_type<endianness>, CipherText>;
    using pinput_marshaling_type =
        nil::crypto3::marshalling::types::r1cs_gg_ppzksnark_primary_input<nil::marshalling::field_type<endianness>,
                                                                          primary_input_type>;

    template<typename MarshalingType, typename InputObj, typename F>
    static std::vector<std::uint8_t> serialize_obj(const InputObj &in_obj, const std::function<F> &f) {
        MarshalingType filled_val = f(in_obj);
        std::vector<std::uint8_t> blob(filled_val.length());
        auto it = std::begin(blob);
        nil::marshalling::status_type status = filled_val.write(it, blob.size());
        return blob;
    }

    template<typename Path, typename Blob>
    static void write_obj(const Path &path, std::initializer_list<Blob> blobs) {
        std::ofstream out(path, std::ios_base::binary);
        for (const auto &blob : blobs) {
            for (const auto b : blob) {
                out << b;
            }
        }
        out.close();
    }

    static void write_data(std::size_t proof_idx, const boost::program_options::variables_map &vm,
                           const verification_key_type &vk, const PublicKey &pubkey, const proof_type &proof,
                           const primary_input_type &pinput, const CipherText &ct, const primary_input_type &eid,
                           const primary_input_type &sn, const primary_input_type &rt) {
        auto proof_blob = serialize_obj<proof_marshaling_type>(
            proof,
            std::function(nil::crypto3::marshalling::types::fill_r1cs_gg_ppzksnark_proof<proof_type, endianness>));
        if (vm.count("proof-output")) {
            auto filename = vm["proof-output"].as<std::string>() + std::to_string(proof_idx) + ".bin";
            write_obj(std::filesystem::path(filename), {proof_blob});
        }

        auto vk_blob = serialize_obj<verification_key_marshaling_type>(
            vk,
            std::function(
                nil::crypto3::marshalling::types::fill_r1cs_gg_ppzksnark_verification_key<verification_key_type,
                                                                                          endianness>));
        if (vm.count("verifying-key-output")) {
            auto filename = vm["verifying-key-output"].as<std::string>() + std::to_string(proof_idx) + ".bin";
            write_obj(std::filesystem::path(filename), {vk_blob});
        }

        auto pubkey_blob = serialize_obj<public_key_marshaling_type>(
            pubkey, std::function(nil::crypto3::marshalling::types::fill_pubkey_key<PublicKey, endianness>));
        if (vm.count("public-key-output")) {
            auto filename = vm["public-key-output"].as<std::string>() + std::to_string(proof_idx) + ".bin";
            write_obj(std::filesystem::path(filename), {pubkey_blob});
        }

        auto pinput_blob = serialize_obj<pinput_marshaling_type>(
            pinput,
            std::function(nil::crypto3::marshalling::types::fill_r1cs_gg_ppzksnark_primary_input<primary_input_type,
                                                                                                 endianness>));
        if (vm.count("primary-input-output")) {
            auto filename = vm["primary-input-output"].as<std::string>() + std::to_string(proof_idx) + ".bin";
            write_obj(std::filesystem::path(filename), {pinput_blob});
        }

        auto ct_blob = serialize_obj<ct_marshaling_type>(
            ct,
            std::function(
                nil::crypto3::marshalling::types::fill_r1cs_gg_ppzksnark_encrypted_primary_input<CipherText,
                                                                                                 endianness>));
        if (vm.count("cipher-text-output")) {
            auto filename = vm["cipher-text-output"].as<std::string>() + std::to_string(proof_idx) + ".bin";
            write_obj(std::filesystem::path(filename), {ct_blob});
        }

        auto eid_blob = serialize_obj<pinput_marshaling_type>(
            eid,
            std::function(nil::crypto3::marshalling::types::fill_r1cs_gg_ppzksnark_primary_input<primary_input_type,
                                                                                                 endianness>));
        if (vm.count("eid-output")) {
            auto filename = vm["eid-output"].as<std::string>() + std::to_string(proof_idx) + ".bin";
            write_obj(std::filesystem::path(filename), {eid_blob});
        }

        auto sn_blob = serialize_obj<pinput_marshaling_type>(
            sn,
            std::function(nil::crypto3::marshalling::types::fill_r1cs_gg_ppzksnark_primary_input<primary_input_type,
                                                                                                 endianness>));
        if (vm.count("sn-output")) {
            auto filename = vm["sn-output"].as<std::string>() + std::to_string(proof_idx) + ".bin";
            write_obj(std::filesystem::path(filename), {sn_blob});
        }

        auto rt_blob = serialize_obj<pinput_marshaling_type>(
            rt,
            std::function(nil::crypto3::marshalling::types::fill_r1cs_gg_ppzksnark_primary_input<primary_input_type,
                                                                                                 endianness>));
        if (vm.count("rt-output")) {
            auto filename = vm["rt-output"].as<std::string>() + std::to_string(proof_idx) + ".bin";
            write_obj(std::filesystem::path(filename), {rt_blob});
        }

        if (vm.count("verifier-input-output")) {
            auto filename = vm["verifier-input-output"].as<std::string>() + std::to_string(proof_idx) + ".bin";
            auto filename1 = vm["verifier-input-output"].as<std::string>() + std::string("_chunked") + std::to_string(proof_idx) + ".bin";
            write_obj(std::filesystem::path(filename), {proof_blob, vk_blob, pubkey_blob, ct_blob, pinput_blob});
            write_obj(std::filesystem::path(filename1), {proof_blob, vk_blob, pubkey_blob, ct_blob, eid_blob, sn_blob, rt_blob});
        }
    }
};

struct enc_input_policy {
    using pairing_curve_type = curves::bls12_381;
    using curve_type = curves::jubjub;
    using base_points_generator_hash_type = hashes::sha2<256>;
    using hash_params = hashes::find_group_hash_default_params;
    using hash_component = components::pedersen<curve_type, base_points_generator_hash_type, hash_params>;
    using hash_type = typename hash_component::hash_type;
    using merkle_hash_component = hash_component;
    using merkle_hash_type = typename merkle_hash_component::hash_type;
    using field_type = typename hash_component::field_type;
    static constexpr std::size_t arity = 2;
    static constexpr std::size_t tree_depth = 2;
    using voting_component =
        components::encrypted_input_voting<arity, hash_component, merkle_hash_component, field_type>;
    using merkle_proof_component = typename voting_component::merkle_proof_component;
    using encryption_scheme_type = elgamal_verifiable<pairing_curve_type>;
    using proof_system = typename encryption_scheme_type::proof_system_type;
    using marshaling_data_type =
        marshaling_verification_data_groth16_encrypted_input<proof_system,
                                                             typename encryption_scheme_type::public_key_type,
                                                             typename encryption_scheme_type::cipher_type::first_type>;
};

template<typename ValueType, std::size_t N>
typename std::enable_if<std::is_unsigned<ValueType>::value, std::vector<std::array<ValueType, N>>>::type
    generate_random_data(std::size_t leaf_number) {
    std::vector<std::array<ValueType, N>> v;
    for (std::size_t i = 0; i < leaf_number; ++i) {
        std::array<ValueType, N> leaf;
        std::generate(std::begin(leaf), std::end(leaf),
                      [&]() { return std::rand() % (std::numeric_limits<ValueType>::max() + 1); });
        v.emplace_back(leaf);
    }
    return v;
}

void process_encrypted_input_mode(const boost::program_options::variables_map &vm) {
    std::size_t tree_depth = 0;
    if (vm.count("tree-depth")) {
        tree_depth = vm["tree-depth"].as<std::size_t>();
    } else {
        std::cerr << "Tree depth is not specified!" << std::endl;
    }

    std::size_t participants_number = 1 << tree_depth;
    std::cout << "There will be " << participants_number << " participants in voting." << std::endl;

    constexpr std::size_t secret_key_bits = enc_input_policy::hash_type::digest_bits;
    constexpr std::size_t public_key_bits = secret_key_bits;
    auto secret_keys = generate_random_data<bool, secret_key_bits>(participants_number);
    std::vector<std::array<bool, public_key_bits>> public_keys;
    auto j = 0;
    for (const auto &sk : secret_keys) {
        std::array<bool, enc_input_policy::hash_type::digest_bits> pk;
        hash<enc_input_policy::merkle_hash_type>(sk, std::begin(pk));
        public_keys.emplace_back(pk);
        std::cout << "Public key of the Voter " << j++ << ": ";
        for (auto c : pk) {
            std::cout << int(c);
        }
        std::cout << std::endl;
    }
    std::cout << "Participants key pairs generated." << std::endl;

    std::cout << "Merkle tree generation upon participants public keys started..." << std::endl;
    containers::merkle_tree<enc_input_policy::merkle_hash_type, enc_input_policy::arity> tree(public_keys);
    std::cout << "Merkle tree generation finished." << std::endl;

    const std::size_t eid_size = 64;
    std::vector<bool> eid(eid_size);
    std::generate(eid.begin(), eid.end(), [&]() { return std::rand() % 2; });
    std::cout << "Voting session (eid) is: ";
    for (auto i : eid) {
        std::cout << int(i);
    }
    std::cout << std::endl;

    std::size_t msg_size = 7;
    std::cout << "Voting system administrator generates R1CS..." << std::endl;
    components::blueprint<enc_input_policy::field_type> bp;
    components::block_variable<enc_input_policy::field_type> m_block(bp, msg_size);
    components::block_variable<enc_input_policy::field_type> eid_block(bp, eid.size());
    components::digest_variable<enc_input_policy::field_type> sn_digest(bp,
                                                                        enc_input_policy::hash_component::digest_bits);
    components::digest_variable<enc_input_policy::field_type> root_digest(
        bp, enc_input_policy::merkle_hash_component::digest_bits);
    components::blueprint_variable_vector<enc_input_policy::field_type> address_bits_va;
    address_bits_va.allocate(bp, enc_input_policy::tree_depth);
    enc_input_policy::merkle_proof_component path_var(bp, enc_input_policy::tree_depth);
    components::block_variable<enc_input_policy::field_type> sk_block(bp, secret_key_bits);
    enc_input_policy::voting_component vote_var(bp, m_block, eid_block, sn_digest, root_digest, address_bits_va,
                                                path_var, sk_block,
                                                components::blueprint_variable<enc_input_policy::field_type>(0));
    path_var.generate_r1cs_constraints();
    vote_var.generate_r1cs_constraints();
    std::cout << "R1CS generation finished." << std::endl;
    std::cout << "Constraints number in the generated R1CS: " << bp.num_constraints() << std::endl;
    bp.set_input_sizes(vote_var.get_input_size());

    std::cout << "Administrator generates CRS..." << std::endl;
    typename enc_input_policy::proof_system::keypair_type gg_keypair =
        snark::generate<enc_input_policy::proof_system>(bp.get_constraint_system());
    std::cout << "CRS generation finished." << std::endl;

    std::cout << "Administrator generates private, public and verification keys for El-Gamal verifiable encryption "
                 "scheme..."
              << std::endl;
    random::algebraic_random_device<typename enc_input_policy::pairing_curve_type::scalar_field_type> d;
    std::vector<typename enc_input_policy::pairing_curve_type::scalar_field_type::value_type> rnd;
    for (std::size_t i = 0; i < msg_size * 3 + 2; ++i) {
        rnd.emplace_back(d());
    }
    typename enc_input_policy::encryption_scheme_type::keypair_type keypair =
        generate_keypair<enc_input_policy::encryption_scheme_type,
                         modes::verifiable_encryption<enc_input_policy::encryption_scheme_type>>(
            rnd, {gg_keypair, msg_size});
    std::cout << "Private, public and verification keys for El-Gamal verifiable encryption scheme generated."
              << std::endl
              << std::endl;
    std::cout << "====================================================================" << std::endl << std::endl;

    std::vector<typename enc_input_policy::encryption_scheme_type::cipher_type> ct_n;

    for (std::size_t i = 0; i < participants_number; ++i) {

        std::size_t proof_idx = i;
        std::cout << "Participant with index " << proof_idx << " (vote sender) generates its merkle copath."
                  << std::endl;
        containers::merkle_proof<enc_input_policy::merkle_hash_type, enc_input_policy::arity> proof(tree, proof_idx);
        auto tree_pk_leaf = tree[proof_idx];

        std::vector<bool> m(msg_size, false);
        m[std::rand() % m.size()] = true;
        std::cout << "Voter " << proof_idx << " is willing to vote with the following ballot: { ";
        for (auto m_i : m) {
            std::cout << int(m_i);
        }
        std::cout << " }" << std::endl;
        std::vector<typename enc_input_policy::pairing_curve_type::scalar_field_type::value_type> m_field;
        for (const auto m_i : m) {
            m_field.emplace_back(std::size_t(m_i));
        }

        std::vector<bool> eid_sk;
        std::copy(std::cbegin(eid), std::cend(eid), std::back_inserter(eid_sk));
        std::copy(std::cbegin(secret_keys[proof_idx]), std::cend(secret_keys[proof_idx]), std::back_inserter(eid_sk));
        std::vector<bool> sn = hash<enc_input_policy::hash_type>(eid_sk);
        std::cout << "Sender has following serial number (sn) in current session: ";
        for (auto i : sn) {
            std::cout << int(i);
        }
        std::cout << std::endl;

        // BOOST_ASSERT(!bp.is_satisfied());
        path_var.generate_r1cs_witness(proof, true);
        if (bp.is_satisfied()) std::abort();
        address_bits_va.fill_with_bits_of_ulong(bp, path_var.address);
        if (bp.is_satisfied()) std::abort();
        if (address_bits_va.get_field_element_from_bits(bp) != path_var.address) std::abort();
        m_block.generate_r1cs_witness(m);
        if (bp.is_satisfied()) std::abort();
        eid_block.generate_r1cs_witness(eid);
        if (bp.is_satisfied()) std::abort();
        sk_block.generate_r1cs_witness(secret_keys[proof_idx]);
        if (bp.is_satisfied()) std::abort();
        vote_var.generate_r1cs_witness(tree.root(), sn);
        if (!bp.is_satisfied()) std::abort();

        std::cout << "Voter " << proof_idx << " generates its vote consisting of proof and cipher text..." << std::endl;
        typename enc_input_policy::encryption_scheme_type::cipher_type cipher_text =
            encrypt<enc_input_policy::encryption_scheme_type,
                    modes::verifiable_encryption<enc_input_policy::encryption_scheme_type>>(
                m_field, {d(), std::get<0>(keypair), gg_keypair, bp.primary_input(), bp.auxiliary_input()});
        ct_n.push_back(cipher_text);
        std::cout << "Vote generated." << std::endl;

        //    std::cout << "Marshalling started..." << std::endl;
        //    typename enc_input_policy::proof_system::primary_input_type pinput = bp.primary_input();
        //    enc_input_policy::marshaling_data_type::write_data(
        //        vm, gg_keypair.second, std::get<0>(keypair), cipher_text.second,
        //        typename enc_input_policy::proof_system::primary_input_type {std::cbegin(pinput) + m.size(),
        //        std::cend(pinput)}, cipher_text.first);
        //    std::cout << "Marshalling finished." << std::endl;

        std::cout << "Rerandomization of the cipher text and proof started..." << std::endl;
        std::vector<typename enc_input_policy::pairing_curve_type::scalar_field_type::value_type> rnd_rerandomization;
        for (std::size_t i = 0; i < 3; ++i) {
            rnd_rerandomization.emplace_back(d());
        }
        typename enc_input_policy::encryption_scheme_type::cipher_type rerand_cipher_text =
            rerandomize<enc_input_policy::encryption_scheme_type>(
                rnd_rerandomization, cipher_text.first, {std::get<0>(keypair), gg_keypair, cipher_text.second});
        std::cout << "Rerandomization finished." << std::endl;

        std::cout << "Marshalling started..." << std::endl;
        std::size_t eid_offset = m.size();
        std::size_t sn_offset = eid_offset + eid.size();
        std::size_t rt_offset = sn_offset + sn.size();
        std::size_t rt_offset_end = rt_offset + tree.root().size();
        typename enc_input_policy::proof_system::primary_input_type pinput = bp.primary_input();
        if (std::cbegin(pinput) + rt_offset_end != std::cend(pinput)) std::abort();
        enc_input_policy::marshaling_data_type::write_data(
            proof_idx, vm, gg_keypair.second, std::get<0>(keypair), rerand_cipher_text.second,
            typename enc_input_policy::proof_system::primary_input_type {std::cbegin(pinput) + eid_offset,
                                                                         std::cend(pinput)},
            rerand_cipher_text.first,
            typename enc_input_policy::proof_system::primary_input_type {std::cbegin(pinput) + eid_offset,
                                                                         std::cbegin(pinput) + sn_offset},
            typename enc_input_policy::proof_system::primary_input_type {std::cbegin(pinput) + sn_offset,
                                                                         std::cbegin(pinput) + rt_offset},
            typename enc_input_policy::proof_system::primary_input_type {std::cbegin(pinput) + rt_offset,
                                                                         std::cbegin(pinput) + rt_offset_end});
        std::cout << "Marshalling finished." << std::endl;

        std::cout << "Sender verifies rerandomized encrypted ballot and proof..." << std::endl;
        bool enc_verification_ans = verify_encryption<enc_input_policy::encryption_scheme_type>(
            rerand_cipher_text.first,
            {std::get<0>(keypair), gg_keypair.second, rerand_cipher_text.second,
             typename enc_input_policy::proof_system::primary_input_type {std::cbegin(pinput) + m.size(),
                                                                          std::cend(pinput)}});
        if (!enc_verification_ans) std::abort();
        std::cout << "Encryption verification of rerandomazed cipher text and proof finished." << std::endl;

        std::cout << "Administrator decrypts ballot from rerandomized cipher text and generates decryption proof..."
                  << std::endl;
        typename enc_input_policy::encryption_scheme_type::decipher_type decipher_rerand_text =
            decrypt<enc_input_policy::encryption_scheme_type,
                    modes::verifiable_encryption<enc_input_policy::encryption_scheme_type>>(
                rerand_cipher_text.first, {std::get<1>(keypair), std::get<2>(keypair), gg_keypair});
        if (decipher_rerand_text.first.size() != m_field.size()) std::abort();
        for (std::size_t i = 0; i < m_field.size(); ++i) {
            if (decipher_rerand_text.first[i] != m_field[i]) std::abort();
        }
        std::cout << "Decryption finished." << std::endl;

        std::cout << "Any voter could verify decryption using decryption proof..." << std::endl;
        bool dec_verification_ans = verify_decryption<enc_input_policy::encryption_scheme_type>(
            rerand_cipher_text.first, decipher_rerand_text.first,
            {std::get<2>(keypair), gg_keypair, decipher_rerand_text.second});
        if (!dec_verification_ans) std::abort();
        std::cout << "Decryption verification finished." << std::endl << std::endl;
        std::cout << "====================================================================" << std::endl << std::endl;
    }

    std::cout << "Tally results." << std::endl;
    auto ct_it = std::cbegin(ct_n);
    auto ct_ = ct_it->first;
    ct_it++;
    while (ct_it != std::cend(ct_n)) {
        for (std::size_t i = 0; i < std::size(ct_); ++i) {
            ct_[i] = ct_[i] + ct_it->first[i];
        }
        ct_it++;
    }

    std::cout << "Deciphered results of voting:" << std::endl;
    typename enc_input_policy::encryption_scheme_type::decipher_type decipher_rerand_sum_text =
        decrypt<enc_input_policy::encryption_scheme_type,
                modes::verifiable_encryption<enc_input_policy::encryption_scheme_type>>(
            ct_, {std::get<1>(keypair), std::get<2>(keypair), gg_keypair});
    if (decipher_rerand_sum_text.first.size() != msg_size) std::abort();
    for (std::size_t i = 0; i < msg_size; ++i) {
        std::cout << decipher_rerand_sum_text.first[i].data << ", ";
    }
    std::cout << std::endl;

    std::cout << "Verification of the deciphered tally result." << std::endl;
    bool dec_verification_ans = verify_decryption<enc_input_policy::encryption_scheme_type>(
        ct_, decipher_rerand_sum_text.first,
        {std::get<2>(keypair), gg_keypair, decipher_rerand_sum_text.second});
    if (!dec_verification_ans) std::abort();
    std::cout << "Verification succeded" << std::endl;
}

int main(int argc, char *argv[]) {
    using curve_type = algebra::curves::bls12<381>;
    using scalar_field_type = typename curve_type::scalar_field_type;
    using endianness = nil::marshalling::option::big_endian;
    using proof_system_type = zk::snark::r1cs_gg_ppzksnark<curve_type>;

    std::string mode;
    std::size_t tree_depth;
    boost::program_options::options_description desc(
        "R1CS Generic Group PreProcessing Zero-Knowledge Succinct Non-interactive ARgument of Knowledge "
        "(https://eprint.iacr.org/2016/260.pdf) CLI Proof Generator.");
    // clang-format off
    desc.add_options()
    ("help,h", "Display help message.")
    ("version,v", "Display version.")
    ("mode,m", boost::program_options::value(&mode)->default_value("basic"),"Proof system processing mode, allowed values: basic, encrypted_input.")
    ("proof-output,po", boost::program_options::value<std::string>()->default_value("proof"), "Proof output path.")
    ("primary-input-output,pio", boost::program_options::value<std::string>()->default_value("primary_input"), "Primary input output path.")
    ("proving-key-output,pko", boost::program_options::value<std::string>()->default_value("proving_key"), "Proving key output path.")
    ("verifying-key-output,vko", boost::program_options::value<std::string>()->default_value("verification_key"), "Verification output path.")
    ("verifier-input-output,vio", boost::program_options::value<std::string>()->default_value("verification_input"), "Verification input output path.")
    ("public-key-output,pubko", boost::program_options::value<std::string>()->default_value("public_key"), "Public key output path (for encrypted_input mode only).")
    ("cipher-text-output,cto", boost::program_options::value<std::string>()->default_value("cipher_text"), "Cipher text output path (for encrypted_input mode only).")
    ("eid-output,eido", boost::program_options::value<std::string>()->default_value("eid"), "Session id output path (for encrypted_input mode only).")
    ("sn-output,sno", boost::program_options::value<std::string>()->default_value("sn"), "Serial number output path (for encrypted_input mode only).")
    ("rt-output,rto", boost::program_options::value<std::string>()->default_value("rt"), "Session id output path (for encrypted_input mode only).")
    ("tree-depth,td", boost::program_options::value<std::size_t>()->default_value(enc_input_policy::tree_depth), "Depth of Merkle tree built upon participants' public keys (for encrypted_input mode only).");
    // clang-format on

    boost::program_options::variables_map vm;
    boost::program_options::store(boost::program_options::command_line_parser(argc, argv).options(desc).run(), vm);
    boost::program_options::notify(vm);

    if (vm.count("help") || argc < 2) {
        std::cout << desc << std::endl;
        return 0;
    }

    if (!vm.count("mode")) {
        std::cout << desc << std::endl;
        return 0;
    } else if (vm["mode"].as<std::string>() == "basic") {
        process_basic_mode<curve_type, endianness, proof_system_type>(vm);
    } else if (vm["mode"].as<std::string>() == "encrypted_input") {
        process_encrypted_input_mode(vm);
    } else {
        std::cout << desc << std::endl;
        return 0;
    }

    return 0;
}