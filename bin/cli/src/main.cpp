//---------------------------------------------------------------------------//
// Copyright (c) 2018-2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Ilias Khairullin <ilias@nil.foundation>
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
#include <nil/crypto3/marshalling/zk/types/r1cs_gg_ppzksnark/proving_key.hpp>

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

template<typename FieldParams>
void print_field_element(std::ostream &os, const typename fields::detail::element_fp<FieldParams> &e) {
    std::cout << e.data << std::endl;
}

template<typename FieldParams>
void print_field_element(std::ostream &os, const typename fields::detail::element_fp2<FieldParams> &e) {
    std::cout << e.data[0].data << ", " << e.data[1].data << std::endl;
}

template<typename CurveParams, typename Form, typename Coordinates>
typename std::enable_if<std::is_same<Coordinates, curves::coordinates::projective>::value ||
                        std::is_same<Coordinates, curves::coordinates::jacobian_with_a4_0>::value ||
                        std::is_same<Coordinates, curves::coordinates::inverted>::value>::type
    print_curve_point(std::ostream &os, const curves::detail::curve_element<CurveParams, Form, Coordinates> &p) {
    os << "( X: [";
    print_field_element(os, p.X);
    os << "], Y: [";
    print_field_element(os, p.Y);
    os << "], Z:[";
    print_field_element(os, p.Z);
    os << "] )" << std::endl;
}

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

    if (vm.count("r1cs-verification-key-output")) {
        std::ofstream out(vm["r1cs-verification-key-output"].as<std::filesystem::path>(), std::ios_base::binary);
        for (const auto &v : verification_key_byteblob) {
            out << v;
        }
        out.close();
    }

    if (vm.count("r1cs-proof-output")) {
        std::ofstream out(vm["r1cs-proof-output"].as<std::filesystem::path>(), std::ios_base::binary);
        for (const auto &v : proof_byteblob) {
            out << v;
        }
        out.close();
    }

    if (vm.count("r1cs-primary-input-output")) {
        std::ofstream out(vm["r1cs-primary-input-output"].as<std::filesystem::path>(), std::ios_base::binary);
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

    if (vm.count("r1cs-verifier-input-output")) {
        std::vector<std::uint8_t> verifier_input_output_byteblob(proof_byteblob.begin(), proof_byteblob.end());

        verifier_input_output_byteblob.insert(verifier_input_output_byteblob.end(), primary_input_byteblob.begin(),
                                              primary_input_byteblob.end());
        verifier_input_output_byteblob.insert(verifier_input_output_byteblob.end(), verification_key_byteblob.begin(),
                                              verification_key_byteblob.end());

        std::ofstream poutf(vm["r1cs-verifier-input-output"].as<std::filesystem::path>(), std::ios_base::binary);
        for (const auto &v : verifier_input_output_byteblob) {
            poutf << v;
        }
        poutf.close();
    }
}

struct marshaling_verification_data_groth16_encrypted_input;

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
    static constexpr std::size_t msg_size = 7;
    static constexpr std::size_t secret_key_bits = hash_type::digest_bits;
    static constexpr std::size_t public_key_bits = secret_key_bits;
};

struct marshaling_policy {
    using scalar_field_value_type =
        typename enc_input_policy::encryption_scheme_type::curve_type::scalar_field_type::value_type;
    using proof_type = typename enc_input_policy::proof_system::proof_type;
    using verification_key_type = typename enc_input_policy::proof_system::verification_key_type;
    using proving_key_type = typename enc_input_policy::proof_system::proving_key_type;
    using primary_input_type = typename enc_input_policy::proof_system::primary_input_type;
    using elgamal_public_key_type = typename enc_input_policy::encryption_scheme_type::public_key_type;
    using elgamal_private_key_type = typename enc_input_policy::encryption_scheme_type::private_key_type;
    using elgamal_verification_key_type = typename enc_input_policy::encryption_scheme_type::verification_key_type;

    using endianness = nil::marshalling::option::big_endian;
    using r1cs_proof_marshaling_type =
        nil::crypto3::marshalling::types::r1cs_gg_ppzksnark_proof<nil::marshalling::field_type<endianness>, proof_type>;
    using r1cs_verification_key_marshaling_type =
        nil::crypto3::marshalling::types::r1cs_gg_ppzksnark_extended_verification_key<
            nil::marshalling::field_type<endianness>, verification_key_type>;
    using r1cs_proving_key_marshalling_type =
        nil::crypto3::marshalling::types::r1cs_gg_ppzksnark_proving_key<nil::marshalling::field_type<endianness>,
                                                                        proving_key_type>;
    using public_key_marshaling_type =
        nil::crypto3::marshalling::types::elgamal_verifiable_public_key<nil::marshalling::field_type<endianness>,
                                                                        elgamal_public_key_type>;
    using secret_key_marshaling_type =
        nil::crypto3::marshalling::types::elgamal_verifiable_private_key<nil::marshalling::field_type<endianness>,
                                                                         elgamal_private_key_type>;
    using verification_key_marshaling_type =
        nil::crypto3::marshalling::types::elgamal_verifiable_verification_key<nil::marshalling::field_type<endianness>,
                                                                              elgamal_verification_key_type>;
    using ct_marshaling_type = nil::crypto3::marshalling::types::r1cs_gg_ppzksnark_encrypted_primary_input<
        nil::marshalling::field_type<endianness>, enc_input_policy::encryption_scheme_type::cipher_type::first_type>;
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
        if (std::filesystem::exists(path)) {
            std::cout << "File " << path << " exists and won't be overwritten." << std::endl;
            return;
        }
        std::ofstream out(path, std::ios_base::binary);
        for (const auto &blob : blobs) {
            for (const auto b : blob) {
                out << b;
            }
        }
        out.close();
    }

    template<typename MarshalingType, typename ReturnType, typename InputBlob, typename F>
    static ReturnType deserialize_obj(const InputBlob &blob, const std::function<F> &f) {
        MarshalingType marshaling_obj;
        auto it = std::cbegin(blob);
        nil::marshalling::status_type status = marshaling_obj.read(it, blob.size());
        return f(marshaling_obj);
    }

    template<typename Path>
    static std::vector<std::uint8_t> read_obj(const Path &path) {
        if (!std::filesystem::exists(path)) {
            std::cerr << "File " << path << " doesn't exist, make sure you created it." << std::endl;
            std::exit(1);
        }
        std::ifstream in(path, std::ios_base::binary);
        std::stringstream buffer;
        buffer << in.rdbuf();
        auto blob_str = buffer.str();
        return {std::cbegin(blob_str), std::cend(blob_str)};
    }

    static void write_initial_phase_voter_data(const boost::program_options::variables_map &vm,
                                               const std::vector<scalar_field_value_type> &voter_pubkey,
                                               const std::vector<scalar_field_value_type> &voter_skey, std::size_t i) {
        auto pubkey_blob = serialize_obj<pinput_marshaling_type>(
            voter_pubkey,
            std::function(nil::crypto3::marshalling::types::fill_r1cs_gg_ppzksnark_primary_input<primary_input_type,
                                                                                                 endianness>));
        if (vm.count("voter-public-key-output")) {
            auto filename = vm["voter-public-key-output"].as<std::string>() + std::to_string(i) + ".bin";
            write_obj(std::filesystem::path(filename), {pubkey_blob});
        }

        auto sk_blob = serialize_obj<pinput_marshaling_type>(
            voter_skey,
            std::function(nil::crypto3::marshalling::types::fill_r1cs_gg_ppzksnark_primary_input<primary_input_type,
                                                                                                 endianness>));
        if (vm.count("voter-secret-key-output")) {
            auto filename = vm["voter-secret-key-output"].as<std::string>() + std::to_string(i) + ".bin";
            write_obj(std::filesystem::path(filename), {sk_blob});
        }
    }

    static void write_initial_phase_admin_data(const boost::program_options::variables_map &vm,
                                               const proving_key_type &pk_crs, const verification_key_type &vk_crs,
                                               const elgamal_public_key_type &pk_eid,
                                               const elgamal_private_key_type &sk_eid,
                                               const elgamal_verification_key_type &vk_eid,
                                               const primary_input_type &eid, const primary_input_type &rt) {
        auto pk_crs_blob = serialize_obj<r1cs_proving_key_marshalling_type>(
            pk_crs,
            std::function(
                nil::crypto3::marshalling::types::fill_r1cs_gg_ppzksnark_proving_key<proving_key_type, endianness>));
        if (vm.count("r1cs-proving-key-output")) {
            auto filename = vm["r1cs-proving-key-output"].as<std::string>() + ".bin";
            write_obj(std::filesystem::path(filename), {pk_crs_blob});
        }

        auto vk_crs_blob = serialize_obj<r1cs_verification_key_marshaling_type>(
            vk_crs,
            std::function(
                nil::crypto3::marshalling::types::fill_r1cs_gg_ppzksnark_verification_key<verification_key_type,
                                                                                          endianness>));
        if (vm.count("r1cs-verification-key-output")) {
            auto filename = vm["r1cs-verification-key-output"].as<std::string>() + ".bin";
            write_obj(std::filesystem::path(filename), {vk_crs_blob});
        }

        auto pk_eid_blob = serialize_obj<public_key_marshaling_type>(
            pk_eid,
            std::function(nil::crypto3::marshalling::types::fill_public_key<elgamal_public_key_type, endianness>));
        if (vm.count("public-key-output")) {
            auto filename = vm["public-key-output"].as<std::string>() + ".bin";
            write_obj(std::filesystem::path(filename), {pk_eid_blob});
        }

        auto sk_eid_blob = serialize_obj<secret_key_marshaling_type>(
            sk_eid,
            std::function(nil::crypto3::marshalling::types::fill_private_key<elgamal_private_key_type, endianness>));
        if (vm.count("secret-key-output")) {
            auto filename = vm["secret-key-output"].as<std::string>() + ".bin";
            write_obj(std::filesystem::path(filename), {sk_eid_blob});
        }

        auto vk_eid_blob = serialize_obj<verification_key_marshaling_type>(
            vk_eid,
            std::function(
                nil::crypto3::marshalling::types::fill_verification_key<elgamal_verification_key_type, endianness>));
        if (vm.count("verification-key-output")) {
            auto filename = vm["verification-key-output"].as<std::string>() + ".bin";
            write_obj(std::filesystem::path(filename), {vk_eid_blob});
        }

        auto eid_blob = serialize_obj<pinput_marshaling_type>(
            eid,
            std::function(nil::crypto3::marshalling::types::fill_r1cs_gg_ppzksnark_primary_input<primary_input_type,
                                                                                                 endianness>));
        if (vm.count("eid-output")) {
            auto filename = vm["eid-output"].as<std::string>() + ".bin";
            write_obj(std::filesystem::path(filename), {eid_blob});
        }

        auto rt_blob = serialize_obj<pinput_marshaling_type>(
            rt,
            std::function(nil::crypto3::marshalling::types::fill_r1cs_gg_ppzksnark_primary_input<primary_input_type,
                                                                                                 endianness>));
        if (vm.count("rt-output")) {
            auto filename = vm["rt-output"].as<std::string>() + ".bin";
            write_obj(std::filesystem::path(filename), {rt_blob});
        }
    }

    static void write_data(std::size_t proof_idx, const boost::program_options::variables_map &vm,
                           const verification_key_type &vk_crs, const elgamal_public_key_type &pk_eid,
                           const proof_type &proof, const primary_input_type &pinput,
                           const enc_input_policy::encryption_scheme_type::cipher_type::first_type &ct,
                           const primary_input_type &eid, const primary_input_type &sn, const primary_input_type &rt) {
        auto proof_blob = serialize_obj<r1cs_proof_marshaling_type>(
            proof,
            std::function(nil::crypto3::marshalling::types::fill_r1cs_gg_ppzksnark_proof<proof_type, endianness>));
        if (vm.count("r1cs-proof-output")) {
            auto filename = vm["r1cs-proof-output"].as<std::string>() + std::to_string(proof_idx) + ".bin";
            write_obj(std::filesystem::path(filename), {proof_blob});
        }

        auto pinput_blob = serialize_obj<pinput_marshaling_type>(
            pinput,
            std::function(nil::crypto3::marshalling::types::fill_r1cs_gg_ppzksnark_primary_input<primary_input_type,
                                                                                                 endianness>));
        if (vm.count("r1cs-primary-input-output")) {
            auto filename = vm["r1cs-primary-input-output"].as<std::string>() + std::to_string(proof_idx) + ".bin";
            write_obj(std::filesystem::path(filename), {pinput_blob});
        }

        auto ct_blob = serialize_obj<ct_marshaling_type>(
            ct,
            std::function(nil::crypto3::marshalling::types::fill_r1cs_gg_ppzksnark_encrypted_primary_input<
                          enc_input_policy::encryption_scheme_type::cipher_type::first_type, endianness>));
        if (vm.count("cipher-text-output")) {
            auto filename = vm["cipher-text-output"].as<std::string>() + std::to_string(proof_idx) + ".bin";
            write_obj(std::filesystem::path(filename), {ct_blob});
        }

        auto eid_blob = serialize_obj<pinput_marshaling_type>(
            eid,
            std::function(nil::crypto3::marshalling::types::fill_r1cs_gg_ppzksnark_primary_input<primary_input_type,
                                                                                                 endianness>));

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

        auto vk_crs_blob = serialize_obj<r1cs_verification_key_marshaling_type>(
            vk_crs,
            std::function(
                nil::crypto3::marshalling::types::fill_r1cs_gg_ppzksnark_verification_key<verification_key_type,
                                                                                          endianness>));
        auto pk_eid_blob = serialize_obj<public_key_marshaling_type>(
            pk_eid,
            std::function(nil::crypto3::marshalling::types::fill_public_key<elgamal_public_key_type, endianness>));
        if (vm.count("r1cs-verifier-input-output")) {
            auto filename = vm["r1cs-verifier-input-output"].as<std::string>() + std::to_string(proof_idx) + ".bin";
            auto filename1 = vm["r1cs-verifier-input-output"].as<std::string>() + std::string("_chunked") +
                             std::to_string(proof_idx) + ".bin";
            write_obj(std::filesystem::path(filename), {proof_blob, vk_crs_blob, pk_eid_blob, ct_blob, pinput_blob});
            write_obj(std::filesystem::path(filename1),
                      {proof_blob, vk_crs_blob, pk_eid_blob, ct_blob, eid_blob, sn_blob, rt_blob});
        }
    }

    static void write_tally_phase_data(const boost::program_options::variables_map &vm,
                                       const typename enc_input_policy::encryption_scheme_type::decipher_type &dec) {
        nil::marshalling::status_type status;
        std::vector<std::uint8_t> dec_proof_blob = nil::marshalling::pack<endianness>(dec.second, status);
        if (vm.count("decryption-proof-output")) {
            auto filename = vm["decryption-proof-output"].as<std::string>() + ".bin";
            write_obj(filename, {
                                    dec_proof_blob,
                                });

            typename enc_input_policy::encryption_scheme_type::decipher_type::second_type constructed_val =
                nil::marshalling::pack<endianness>(dec_proof_blob, status);
            if (!(dec.second == constructed_val))
                std::exit(10);
        }

        auto voting_res_blob = serialize_obj<pinput_marshaling_type>(
            dec.first,
            std::function(nil::crypto3::marshalling::types::fill_r1cs_gg_ppzksnark_primary_input<
                          std::vector<scalar_field_value_type>, endianness>));
        if (vm.count("voting-result-output")) {
            auto filename = vm["voting-result-output"].as<std::string>() + ".bin";
            write_obj(filename, {
                                    voting_res_blob,
                                });
        }
    }

    static std::vector<scalar_field_value_type> read_scalar_vector(std::string file_prefix) {
        auto filename = file_prefix + ".bin";
        return deserialize_obj<pinput_marshaling_type, std::vector<scalar_field_value_type>>(
            read_obj(filename),
            std::function(nil::crypto3::marshalling::types::make_r1cs_gg_ppzksnark_primary_input<
                          std::vector<scalar_field_value_type>, endianness>));
    }

    static std::vector<bool> read_bool_vector(std::string file_prefix) {
        std::vector<bool> result;
        for (const auto &i : read_scalar_vector(file_prefix)) {
            result.emplace_back(i.data);
        }
        return result;
    }

    static std::vector<std::vector<bool>> read_voters_public_keys(const boost::program_options::variables_map &vm) {
        std::size_t participants_number = 1 << vm["tree-depth"].as<std::size_t>();
        std::vector<std::vector<bool>> result;

        for (auto i = 0; i < participants_number; i++) {
            if (vm.count("voter-public-key-output")) {
                result.emplace_back(
                    read_bool_vector(vm["voter-public-key-output"].as<std::string>() + std::to_string(i)));
            }
        }
        return result;
    }

    static elgamal_public_key_type read_pk_eid(const boost::program_options::variables_map &vm) {
        auto pk_eid_blob = read_obj(vm["public-key-output"].as<std::string>() + ".bin");
        return deserialize_obj<public_key_marshaling_type, elgamal_public_key_type>(
            pk_eid_blob,
            std::function(nil::crypto3::marshalling::types::make_public_key<elgamal_public_key_type, endianness>));
    }

    static elgamal_verification_key_type read_vk_eid(const boost::program_options::variables_map &vm) {
        auto vk_eid_blob = read_obj(vm["verification-key-output"].as<std::string>() + ".bin");
        return deserialize_obj<verification_key_marshaling_type, elgamal_verification_key_type>(
            vk_eid_blob,
            std::function(
                nil::crypto3::marshalling::types::make_verification_key<elgamal_verification_key_type, endianness>));
    }

    static elgamal_private_key_type read_sk_eid(const boost::program_options::variables_map &vm) {
        auto sk_eid_blob = read_obj(vm["secret-key-output"].as<std::string>() + ".bin");
        return deserialize_obj<secret_key_marshaling_type, elgamal_private_key_type>(
            sk_eid_blob,
            std::function(nil::crypto3::marshalling::types::make_private_key<elgamal_private_key_type, endianness>));
    }

    static verification_key_type read_vk_crs(const boost::program_options::variables_map &vm) {
        auto vk_crs_blob = read_obj(vm["r1cs-verification-key-output"].as<std::string>() + ".bin");
        return deserialize_obj<r1cs_verification_key_marshaling_type, verification_key_type>(
            vk_crs_blob, std::function(nil::crypto3::marshalling::types::make_r1cs_gg_ppzksnark_verification_key<
                                       verification_key_type, endianness>));
    }

    static proving_key_type read_pk_crs(const boost::program_options::variables_map &vm) {
        auto pk_crs_blob = read_obj(vm["r1cs-proving-key-output"].as<std::string>() + ".bin");
        return deserialize_obj<r1cs_proving_key_marshalling_type, proving_key_type>(
            pk_crs_blob,
            std::function(
                nil::crypto3::marshalling::types::make_r1cs_gg_ppzksnark_proving_key<proving_key_type, endianness>));
    }

    static proof_type read_proof(const boost::program_options::variables_map &vm, std::size_t proof_idx) {
        auto proof_blob = read_obj(vm["r1cs-proof-output"].as<std::string>() + std::to_string(proof_idx) + ".bin");
        return deserialize_obj<r1cs_proof_marshaling_type, proof_type>(
            proof_blob,
            std::function(nil::crypto3::marshalling::types::make_r1cs_gg_ppzksnark_proof<proof_type, endianness>));
    }

    static typename enc_input_policy::encryption_scheme_type::cipher_type::first_type
        read_ct(const boost::program_options::variables_map &vm, std::size_t proof_idx) {
        return deserialize_obj<ct_marshaling_type,
                               typename enc_input_policy::encryption_scheme_type::cipher_type::first_type>(
            read_obj(vm["cipher-text-output"].as<std::string>() + std::to_string(proof_idx) + ".bin"),
            std::function(nil::crypto3::marshalling::types::make_r1cs_gg_ppzksnark_encrypted_primary_input<
                          typename enc_input_policy::encryption_scheme_type::cipher_type::first_type, endianness>));
    }

    static typename enc_input_policy::encryption_scheme_type::decipher_type::second_type
        read_decryption_proof(const boost::program_options::variables_map &vm) {
        auto dec_proof_blob = read_obj(vm["decryption-proof-output"].as<std::string>() + ".bin");
        nil::marshalling::status_type status;
        return static_cast<typename enc_input_policy::encryption_scheme_type::decipher_type::second_type>(
            nil::marshalling::pack<endianness>(dec_proof_blob, status));
    }
};

template<typename ValueType, std::size_t N>
typename std::enable_if<std::is_unsigned<ValueType>::value, std::vector<std::array<ValueType, N>>>::type
    generate_random_data(std::size_t leaf_number) {
    std::vector<std::array<ValueType, N>> v;
    for (std::size_t i = 0; i < leaf_number; ++i) {
        std::array<ValueType, N> leaf {};
        std::generate(std::begin(leaf), std::end(leaf),
                      [&]() { return std::rand() % (std::numeric_limits<ValueType>::max() + 1); });
        v.emplace_back(leaf);
    }
    return v;
}

void process_encrypted_input_mode(const boost::program_options::variables_map &vm) {
    using scalar_field_value_type = typename enc_input_policy::pairing_curve_type::scalar_field_type::value_type;

    std::size_t tree_depth = 0;
    if (vm.count("tree-depth")) {
        tree_depth = vm["tree-depth"].as<std::size_t>();
    } else {
        std::cerr << "Tree depth is not specified!" << std::endl;
        return;
    }

    std::size_t participants_number = 1 << tree_depth;
    std::cout << "There will be " << participants_number << " participants in voting." << std::endl;

    auto secret_keys = generate_random_data<bool, enc_input_policy::secret_key_bits>(participants_number);
    std::vector<std::array<bool, enc_input_policy::public_key_bits>> public_keys;
    std::vector<std::vector<scalar_field_value_type>> public_keys_field;
    std::vector<std::vector<scalar_field_value_type>> secret_keys_field;
    auto j = 0;
    for (const auto &sk : secret_keys) {
        std::array<bool, enc_input_policy::hash_type::digest_bits> pk {};
        hash<enc_input_policy::merkle_hash_type>(sk, std::begin(pk));
        public_keys.emplace_back(pk);
        std::vector<scalar_field_value_type> pk_field;
        std::vector<scalar_field_value_type> sk_field;
        std::cout << "Public key of the Voter " << j << ": ";
        for (auto c : pk) {
            std::cout << int(c);
            pk_field.emplace_back(int(c));
        }
        for (auto c : sk) {
            sk_field.emplace_back(int(c));
        }
        std::cout << std::endl;
        public_keys_field.push_back(pk_field);
        secret_keys_field.push_back(sk_field);
        marshaling_policy::write_initial_phase_voter_data(vm, public_keys_field.back(), secret_keys_field.back(), j);
        ++j;
    }
    std::cout << "Participants key pairs generated." << std::endl;

    std::cout << "Merkle tree generation upon participants public keys started..." << std::endl;
    containers::merkle_tree<enc_input_policy::merkle_hash_type, enc_input_policy::arity> tree(public_keys);
    std::vector<scalar_field_value_type> rt_field;
    for (auto i : tree.root()) {
        rt_field.emplace_back(int(i));
    }
    std::cout << "Merkle tree generation finished." << std::endl;

    const std::size_t eid_size = 64;
    std::vector<bool> eid(eid_size);
    std::vector<scalar_field_value_type> eid_field;
    std::generate(eid.begin(), eid.end(), [&]() { return std::rand() % 2; });
    std::cout << "Voting session (eid) is: ";
    for (auto i : eid) {
        std::cout << int(i);
        eid_field.emplace_back(int(i));
    }
    std::cout << std::endl;

    std::cout << "Voting system administrator generates R1CS..." << std::endl;
    components::blueprint<enc_input_policy::field_type> bp;
    components::block_variable<enc_input_policy::field_type> m_block(bp, enc_input_policy::msg_size);
    components::block_variable<enc_input_policy::field_type> eid_block(bp, eid.size());
    components::digest_variable<enc_input_policy::field_type> sn_digest(bp,
                                                                        enc_input_policy::hash_component::digest_bits);
    components::digest_variable<enc_input_policy::field_type> root_digest(
        bp, enc_input_policy::merkle_hash_component::digest_bits);
    components::blueprint_variable_vector<enc_input_policy::field_type> address_bits_va;
    address_bits_va.allocate(bp, enc_input_policy::tree_depth);
    enc_input_policy::merkle_proof_component path_var(bp, enc_input_policy::tree_depth);
    components::block_variable<enc_input_policy::field_type> sk_block(bp, enc_input_policy::secret_key_bits);
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
    std::vector<scalar_field_value_type> rnd;
    for (std::size_t i = 0; i < enc_input_policy::msg_size * 3 + 2; ++i) {
        rnd.emplace_back(d());
    }
    typename enc_input_policy::encryption_scheme_type::keypair_type keypair =
        generate_keypair<enc_input_policy::encryption_scheme_type,
                         modes::verifiable_encryption<enc_input_policy::encryption_scheme_type>>(
            rnd, {gg_keypair, enc_input_policy::msg_size});
    std::cout << "Private, public and verification keys for El-Gamal verifiable encryption scheme generated."
              << std::endl
              << std::endl;
    std::cout << "====================================================================" << std::endl << std::endl;

    std::cout << "Pre-init administrator marshalling started..." << std::endl;
    marshaling_policy::write_initial_phase_admin_data(vm, gg_keypair.first, gg_keypair.second, std::get<0>(keypair),
                                                      std::get<1>(keypair), std::get<2>(keypair), eid_field, rt_field);
    std::cout << "Marshalling finished." << std::endl;

    std::vector<typename enc_input_policy::encryption_scheme_type::cipher_type> ct_n;

    for (std::size_t i = 0; i < participants_number; ++i) {

        std::size_t proof_idx = i;
        std::cout << "Participant with index " << proof_idx << " (vote sender) generates its merkle copath."
                  << std::endl;
        containers::merkle_proof<enc_input_policy::merkle_hash_type, enc_input_policy::arity> path(tree, proof_idx);
        auto tree_pk_leaf = tree[proof_idx];

        std::vector<bool> m(enc_input_policy::msg_size, false);
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
        std::vector<bool> sn = hash<enc_input_policy::hash_type>(eid_sk);
        std::cout << "Sender has following serial number (sn) in current session: ";
        for (auto i : sn) {
            std::cout << int(i);
        }
        std::cout << std::endl;

        // BOOST_ASSERT(!bp.is_satisfied());
        path_var.generate_r1cs_witness(path, true);
        if (bp.is_satisfied())
            std::exit(1);
        address_bits_va.fill_with_bits_of_ulong(bp, path_var.address);
        if (bp.is_satisfied())
            std::exit(1);
        if (address_bits_va.get_field_element_from_bits(bp) != path_var.address)
            std::exit(1);
        m_block.generate_r1cs_witness(m);
        if (bp.is_satisfied())
            std::exit(1);
        eid_block.generate_r1cs_witness(eid);
        if (bp.is_satisfied())
            std::exit(1);
        sk_block.generate_r1cs_witness(secret_keys[proof_idx]);
        if (bp.is_satisfied())
            std::exit(1);
        vote_var.generate_r1cs_witness(tree.root(), sn);
        if (!bp.is_satisfied())
            std::exit(1);

        std::cout << "Voter " << proof_idx << " generates its vote consisting of proof and cipher text..." << std::endl;
        typename enc_input_policy::encryption_scheme_type::cipher_type cipher_text =
            encrypt<enc_input_policy::encryption_scheme_type,
                    modes::verifiable_encryption<enc_input_policy::encryption_scheme_type>>(
                m_field, {d(), std::get<0>(keypair), gg_keypair, bp.primary_input(), bp.auxiliary_input()});
        ct_n.push_back(cipher_text);
        std::cout << "Vote generated." << std::endl;

        std::cout << "Rerandomization of the cipher text and proof started..." << std::endl;
        std::vector<scalar_field_value_type> rnd_rerandomization;
        for (std::size_t i = 0; i < 3; ++i) {
            rnd_rerandomization.emplace_back(d());
        }
        typename enc_input_policy::encryption_scheme_type::cipher_type rerand_cipher_text =
            rerandomize<enc_input_policy::encryption_scheme_type>(
                rnd_rerandomization, cipher_text.first, {std::get<0>(keypair), gg_keypair, cipher_text.second});
        std::cout << "Rerandomization finished." << std::endl;

        std::cout << "Voter " << proof_idx << " marshalling started..." << std::endl;
        std::size_t eid_offset = m.size();
        std::size_t sn_offset = eid_offset + eid.size();
        std::size_t rt_offset = sn_offset + sn.size();
        std::size_t rt_offset_end = rt_offset + tree.root().size();
        typename enc_input_policy::proof_system::primary_input_type pinput = bp.primary_input();
        if (std::cbegin(pinput) + rt_offset_end != std::cend(pinput))
            std::exit(1);
        if (eid_field != typename enc_input_policy::proof_system::primary_input_type {std::cbegin(pinput) + eid_offset,
                                                                                      std::cbegin(pinput) + sn_offset})
            std::exit(1);
        if (rt_field != typename enc_input_policy::proof_system::primary_input_type {
                            std::cbegin(pinput) + rt_offset, std::cbegin(pinput) + rt_offset_end})
            std::exit(1);
        marshaling_policy::write_data(proof_idx, vm, gg_keypair.second, std::get<0>(keypair), rerand_cipher_text.second,
                                      typename enc_input_policy::proof_system::primary_input_type {
                                          std::cbegin(pinput) + eid_offset, std::cend(pinput)},
                                      rerand_cipher_text.first,
                                      typename enc_input_policy::proof_system::primary_input_type {
                                          std::cbegin(pinput) + eid_offset, std::cbegin(pinput) + sn_offset},
                                      typename enc_input_policy::proof_system::primary_input_type {
                                          std::cbegin(pinput) + sn_offset, std::cbegin(pinput) + rt_offset},
                                      typename enc_input_policy::proof_system::primary_input_type {
                                          std::cbegin(pinput) + rt_offset, std::cbegin(pinput) + rt_offset_end});
        std::cout << "Marshalling finished." << std::endl;

        std::cout << "Sender verifies rerandomized encrypted ballot and proof..." << std::endl;
        bool enc_verification_ans = verify_encryption<enc_input_policy::encryption_scheme_type>(
            rerand_cipher_text.first,
            {std::get<0>(keypair), gg_keypair.second, rerand_cipher_text.second,
             typename enc_input_policy::proof_system::primary_input_type {std::cbegin(pinput) + m.size(),
                                                                          std::cend(pinput)}});
        if (!enc_verification_ans)
            std::exit(1);
        std::cout << "Encryption verification of rerandomazed cipher text and proof finished." << std::endl;

        std::cout << "Administrator decrypts ballot from rerandomized cipher text and generates decryption proof..."
                  << std::endl;
        typename enc_input_policy::encryption_scheme_type::decipher_type decipher_rerand_text =
            decrypt<enc_input_policy::encryption_scheme_type,
                    modes::verifiable_encryption<enc_input_policy::encryption_scheme_type>>(
                rerand_cipher_text.first, {std::get<1>(keypair), std::get<2>(keypair), gg_keypair});
        if (decipher_rerand_text.first.size() != m_field.size())
            std::exit(1);
        for (std::size_t i = 0; i < m_field.size(); ++i) {
            if (decipher_rerand_text.first[i] != m_field[i])
                std::exit(1);
        }
        std::cout << "Decryption finished, decryption proof generated." << std::endl;

        std::cout << "Any voter could verify decryption using decryption proof..." << std::endl;
        bool dec_verification_ans = verify_decryption<enc_input_policy::encryption_scheme_type>(
            rerand_cipher_text.first, decipher_rerand_text.first,
            {std::get<2>(keypair), gg_keypair, decipher_rerand_text.second});
        if (!dec_verification_ans)
            std::exit(1);
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
    if (decipher_rerand_sum_text.first.size() != enc_input_policy::msg_size)
        std::exit(1);
    for (std::size_t i = 0; i < enc_input_policy::msg_size; ++i) {
        std::cout << decipher_rerand_sum_text.first[i].data << ", ";
    }
    std::cout << std::endl;

    std::cout << "Tally phase marshalling started..." << std::endl;
    marshaling_policy::write_tally_phase_data(vm, decipher_rerand_sum_text);
    std::cout << "Marshalling finished." << std::endl;

    std::cout << "Verification of the deciphered tally result." << std::endl;
    bool dec_verification_ans = verify_decryption<enc_input_policy::encryption_scheme_type>(
        ct_, decipher_rerand_sum_text.first, {std::get<2>(keypair), gg_keypair, decipher_rerand_sum_text.second});
    if (!dec_verification_ans)
        std::exit(1);
    std::cout << "Verification succeeded" << std::endl;
}

void process_encrypted_input_mode_init_voter_phase(const boost::program_options::variables_map &vm) {
    using scalar_field_value_type = typename enc_input_policy::pairing_curve_type::scalar_field_type::value_type;

    std::size_t proof_idx = vm["voter-idx"].as<std::size_t>();
    std::cout << "Voter " << proof_idx << " generates its public and secret keys..." << std::endl << std::endl;

    auto secret_keys = generate_random_data<bool, enc_input_policy::secret_key_bits>(1);
    std::vector<std::array<bool, enc_input_policy::public_key_bits>> public_keys;
    std::array<bool, enc_input_policy::hash_type::digest_bits> pk {};
    hash<enc_input_policy::merkle_hash_type>(secret_keys[0], std::begin(pk));
    public_keys.emplace_back(pk);
    std::vector<scalar_field_value_type> pk_field;
    std::vector<scalar_field_value_type> sk_field;
    std::cout << "Public key of the Voter " << proof_idx << ": ";
    for (auto c : pk) {
        std::cout << int(c);
        pk_field.emplace_back(int(c));
    }
    for (auto c : secret_keys[0]) {
        sk_field.emplace_back(int(c));
    }
    std::cout << std::endl;
    marshaling_policy::write_initial_phase_voter_data(vm, pk_field, sk_field, proof_idx);
    std::cout << "Participants key pairs generated." << std::endl;
}

void process_encrypted_input_mode_init_admin_phase(const boost::program_options::variables_map &vm) {
    using scalar_field_value_type = typename enc_input_policy::pairing_curve_type::scalar_field_type::value_type;

    std::cout << "Administrator pre-initializes voting session..." << std::endl << std::endl;

    std::size_t tree_depth = 0;
    if (vm.count("tree-depth")) {
        tree_depth = vm["tree-depth"].as<std::size_t>();
    } else {
        std::cerr << "Tree depth is not specified!" << std::endl;
        return;
    }

    std::cout << "Merkle tree generation upon participants public keys started..." << std::endl;
    auto public_keys = marshaling_policy::read_voters_public_keys(vm);
    containers::merkle_tree<enc_input_policy::merkle_hash_type, enc_input_policy::arity> tree(public_keys);
    std::vector<scalar_field_value_type> rt_field;
    for (auto i : tree.root()) {
        rt_field.emplace_back(int(i));
    }
    std::cout << "Merkle tree generation finished." << std::endl;

    const std::size_t eid_size = 64;
    std::vector<bool> eid(eid_size);
    std::vector<scalar_field_value_type> eid_field;
    std::generate(eid.begin(), eid.end(), [&]() { return std::rand() % 2; });
    std::cout << "Voting session (eid) is: ";
    for (auto i : eid) {
        std::cout << int(i);
        eid_field.emplace_back(int(i));
    }
    std::cout << std::endl;

    std::cout << "Voting system administrator generates R1CS..." << std::endl;
    components::blueprint<enc_input_policy::field_type> bp;
    components::block_variable<enc_input_policy::field_type> m_block(bp, enc_input_policy::msg_size);
    components::block_variable<enc_input_policy::field_type> eid_block(bp, eid.size());
    components::digest_variable<enc_input_policy::field_type> sn_digest(bp,
                                                                        enc_input_policy::hash_component::digest_bits);
    components::digest_variable<enc_input_policy::field_type> root_digest(
        bp, enc_input_policy::merkle_hash_component::digest_bits);
    components::blueprint_variable_vector<enc_input_policy::field_type> address_bits_va;
    address_bits_va.allocate(bp, enc_input_policy::tree_depth);
    enc_input_policy::merkle_proof_component path_var(bp, enc_input_policy::tree_depth);
    components::block_variable<enc_input_policy::field_type> sk_block(bp, enc_input_policy::secret_key_bits);
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
    std::vector<scalar_field_value_type> rnd;
    for (std::size_t i = 0; i < enc_input_policy::msg_size * 3 + 2; ++i) {
        rnd.emplace_back(d());
    }
    typename enc_input_policy::encryption_scheme_type::keypair_type keypair =
        generate_keypair<enc_input_policy::encryption_scheme_type,
                         modes::verifiable_encryption<enc_input_policy::encryption_scheme_type>>(
            rnd, {gg_keypair, enc_input_policy::msg_size});
    std::cout << "Private, public and verification keys for El-Gamal verifiable encryption scheme generated."
              << std::endl
              << std::endl;
    std::cout << "====================================================================" << std::endl << std::endl;

    std::cout << "Pre-init administrator marshalling started..." << std::endl;
    marshaling_policy::write_initial_phase_admin_data(vm, gg_keypair.first, gg_keypair.second, std::get<0>(keypair),
                                                      std::get<1>(keypair), std::get<2>(keypair), eid_field, rt_field);
    std::cout << "Marshalling finished." << std::endl;
}

void process_encrypted_input_mode_vote_phase(const boost::program_options::variables_map &vm) {
    using scalar_field_value_type = typename enc_input_policy::pairing_curve_type::scalar_field_type::value_type;

    std::size_t tree_depth = 0;
    if (vm.count("tree-depth")) {
        tree_depth = vm["tree-depth"].as<std::size_t>();
    } else {
        std::cerr << "Tree depth is not specified!" << std::endl;
        return;
    }
    std::size_t participants_number = 1 << tree_depth;

    std::size_t proof_idx = vm["voter-idx"].as<std::size_t>();
    if (participants_number <= proof_idx) {
        std::cerr << "participants_number <= voter_idx" << std::endl;
        std::exit(1);
    }
    std::cout << "Voter " << proof_idx << " generate encrypted ballot" << std::endl << std::endl;

    std::cout << "Participant with index " << proof_idx << " (vote sender) generates its merkle copath." << std::endl;
    auto public_keys = marshaling_policy::read_voters_public_keys(vm);
    containers::merkle_tree<enc_input_policy::merkle_hash_type, enc_input_policy::arity> tree(public_keys);
    std::vector<scalar_field_value_type> rt_field;
    for (auto i : tree.root()) {
        rt_field.emplace_back(int(i));
    }
    if (rt_field != marshaling_policy::read_scalar_vector(vm["rt-output"].as<std::string>())) {
        std::exit(2);
    }
    containers::merkle_proof<enc_input_policy::merkle_hash_type, enc_input_policy::arity> path(tree, proof_idx);
    auto tree_pk_leaf = tree[proof_idx];

    std::vector<bool> m(enc_input_policy::msg_size, false);
    m[std::rand() % m.size()] = true;
    std::cout << "Voter " << proof_idx << " is willing to vote with the following ballot: { ";
    for (auto m_i : m) {
        std::cout << int(m_i);
    }
    std::cout << " }" << std::endl;
    std::vector<typename enc_input_policy::pairing_curve_type::scalar_field_type::value_type> m_field;
    m_field.reserve(m.size());
    for (const auto m_i : m) {
        m_field.emplace_back(std::size_t(m_i));
    }

    auto eid = marshaling_policy::read_bool_vector(vm["eid-output"].as<std::string>());
    auto sk = marshaling_policy::read_bool_vector(vm["voter-secret-key-output"].as<std::string>() +
                                                  std::to_string(proof_idx));
    std::vector<bool> eid_sk;
    std::copy(std::cbegin(eid), std::cend(eid), std::back_inserter(eid_sk));
    std::copy(std::cbegin(sk), std::cend(sk), std::back_inserter(eid_sk));
    std::vector<bool> sn = hash<enc_input_policy::hash_type>(eid_sk);
    std::cout << "Sender has following serial number (sn) in current session: ";
    for (auto i : sn) {
        std::cout << int(i);
    }
    std::cout << std::endl;

    components::blueprint<enc_input_policy::field_type> bp;
    components::block_variable<enc_input_policy::field_type> m_block(bp, enc_input_policy::msg_size);
    components::block_variable<enc_input_policy::field_type> eid_block(bp, eid.size());
    components::digest_variable<enc_input_policy::field_type> sn_digest(bp,
                                                                        enc_input_policy::hash_component::digest_bits);
    components::digest_variable<enc_input_policy::field_type> root_digest(
        bp, enc_input_policy::merkle_hash_component::digest_bits);
    components::blueprint_variable_vector<enc_input_policy::field_type> address_bits_va;
    address_bits_va.allocate(bp, enc_input_policy::tree_depth);
    enc_input_policy::merkle_proof_component path_var(bp, enc_input_policy::tree_depth);
    components::block_variable<enc_input_policy::field_type> sk_block(bp, enc_input_policy::secret_key_bits);
    enc_input_policy::voting_component vote_var(bp, m_block, eid_block, sn_digest, root_digest, address_bits_va,
                                                path_var, sk_block,
                                                components::blueprint_variable<enc_input_policy::field_type>(0));
    path_var.generate_r1cs_constraints();
    vote_var.generate_r1cs_constraints();
    std::cout << "R1CS generation finished." << std::endl;
    std::cout << "Constraints number in the generated R1CS: " << bp.num_constraints() << std::endl;
    bp.set_input_sizes(vote_var.get_input_size());

    // BOOST_ASSERT(!bp.is_satisfied());
    path_var.generate_r1cs_witness(path, true);
    if (bp.is_satisfied())
        std::exit(1);
    address_bits_va.fill_with_bits_of_ulong(bp, path_var.address);
    if (bp.is_satisfied())
        std::exit(1);
    if (address_bits_va.get_field_element_from_bits(bp) != path_var.address)
        std::exit(1);
    m_block.generate_r1cs_witness(m);
    if (bp.is_satisfied())
        std::exit(1);
    eid_block.generate_r1cs_witness(eid);
    if (bp.is_satisfied())
        std::exit(1);
    sk_block.generate_r1cs_witness(sk);
    if (bp.is_satisfied())
        std::exit(1);
    vote_var.generate_r1cs_witness(tree.root(), sn);
    if (!bp.is_satisfied())
        std::exit(1);

    std::cout << "Voter " << proof_idx << " generates its vote consisting of proof and cipher text..." << std::endl;
    random::algebraic_random_device<typename enc_input_policy::pairing_curve_type::scalar_field_type> d;
    auto pk_eid = marshaling_policy::read_pk_eid(vm);
    typename enc_input_policy::proof_system::keypair_type gg_keypair = {marshaling_policy::read_pk_crs(vm),
                                                                        marshaling_policy::read_vk_crs(vm)};
    typename enc_input_policy::encryption_scheme_type::cipher_type cipher_text =
        encrypt<enc_input_policy::encryption_scheme_type,
                modes::verifiable_encryption<enc_input_policy::encryption_scheme_type>>(
            m_field, {d(), pk_eid, gg_keypair, bp.primary_input(), bp.auxiliary_input()});
    std::cout << "Vote generated." << std::endl;

    std::cout << "Rerandomization of the cipher text and proof started..." << std::endl;
    std::vector<typename enc_input_policy::pairing_curve_type::scalar_field_type::value_type> rnd_rerandomization;
    for (std::size_t i = 0; i < 3; ++i) {
        rnd_rerandomization.emplace_back(d());
    }
    typename enc_input_policy::encryption_scheme_type::cipher_type rerand_cipher_text =
        rerandomize<enc_input_policy::encryption_scheme_type>(rnd_rerandomization, cipher_text.first,
                                                              {pk_eid, gg_keypair, cipher_text.second});
    std::cout << "Rerandomization finished." << std::endl;

    std::cout << "Voter " << proof_idx << " marshalling started..." << std::endl;
    std::size_t eid_offset = m.size();
    std::size_t sn_offset = eid_offset + eid.size();
    std::size_t rt_offset = sn_offset + sn.size();
    std::size_t rt_offset_end = rt_offset + tree.root().size();
    typename enc_input_policy::proof_system::primary_input_type pinput = bp.primary_input();
    marshaling_policy::write_data(proof_idx, vm, gg_keypair.second, pk_eid, rerand_cipher_text.second,
                                  typename enc_input_policy::proof_system::primary_input_type {
                                      std::cbegin(pinput) + eid_offset, std::cend(pinput)},
                                  rerand_cipher_text.first,
                                  typename enc_input_policy::proof_system::primary_input_type {
                                      std::cbegin(pinput) + eid_offset, std::cbegin(pinput) + sn_offset},
                                  typename enc_input_policy::proof_system::primary_input_type {
                                      std::cbegin(pinput) + sn_offset, std::cbegin(pinput) + rt_offset},
                                  typename enc_input_policy::proof_system::primary_input_type {
                                      std::cbegin(pinput) + rt_offset, std::cbegin(pinput) + rt_offset_end});
    std::cout << "Marshalling finished." << std::endl;

    std::cout << "Sender verifies rerandomized encrypted ballot and proof..." << std::endl;
    bool enc_verification_ans = verify_encryption<enc_input_policy::encryption_scheme_type>(
        rerand_cipher_text.first,
        {pk_eid, gg_keypair.second, rerand_cipher_text.second,
         typename enc_input_policy::proof_system::primary_input_type {std::cbegin(pinput) + m.size(),
                                                                      std::cend(pinput)}});
    if (!enc_verification_ans)
        std::exit(1);
    std::cout << "Encryption verification of rerandomazed cipher text and proof finished." << std::endl;
}

void process_encrypted_input_mode_vote_verify_phase(const boost::program_options::variables_map &vm) {
}

void process_encrypted_input_mode_tally_admin_phase(const boost::program_options::variables_map &vm) {
    std::cout << "Administrator processes tally phase - aggregates encrypted ballots, decrypts aggregated ballot, "
                 "generate decryption proof..."
              << std::endl
              << std::endl;

    std::size_t tree_depth = 0;
    if (vm.count("tree-depth")) {
        tree_depth = vm["tree-depth"].as<std::size_t>();
    } else {
        std::cerr << "Tree depth is not specified!" << std::endl;
        return;
    }
    std::size_t participants_number = 1 << tree_depth;

    auto ct_agg = marshaling_policy::read_ct(vm, 0);
    for (auto proof_idx = 1; proof_idx < participants_number; proof_idx++) {
        auto ct_i = marshaling_policy::read_ct(vm, proof_idx);
        if (std::size(ct_agg) != std::size(ct_i)) {
            std::cerr << "Wrong size of the ct" << std::endl;
            std::exit(2);
        }
        for (std::size_t i = 0; i < std::size(ct_i); ++i) {
            ct_agg[i] = ct_agg[i] + ct_i[i];
        }
    }

    auto sk_eid = marshaling_policy::read_sk_eid(vm);
    auto vk_eid = marshaling_policy::read_vk_eid(vm);
    typename enc_input_policy::proof_system::keypair_type gg_keypair = {marshaling_policy::read_pk_crs(vm),
                                                                        marshaling_policy::read_vk_crs(vm)};
    std::cout << "Deciphered results of voting:" << std::endl;
    typename enc_input_policy::encryption_scheme_type::decipher_type decipher_rerand_sum_text =
        decrypt<enc_input_policy::encryption_scheme_type,
                modes::verifiable_encryption<enc_input_policy::encryption_scheme_type>>(ct_agg,
                                                                                        {sk_eid, vk_eid, gg_keypair});
    if (decipher_rerand_sum_text.first.size() != enc_input_policy::msg_size) {
        std::cerr << "Deciphered lens not equal" << decipher_rerand_sum_text.first.size()
                  << " != " << enc_input_policy::msg_size << std::endl;
        std::exit(1);
    }
    for (std::size_t i = 0; i < enc_input_policy::msg_size; ++i) {
        std::cout << decipher_rerand_sum_text.first[i].data << ", ";
    }
    std::cout << std::endl;

    std::cout << "Tally phase marshalling started..." << std::endl;
    marshaling_policy::write_tally_phase_data(vm, decipher_rerand_sum_text);
    std::cout << "Marshalling finished." << std::endl;
}

void process_encrypted_input_mode_tally_voter_phase(const boost::program_options::variables_map &vm) {
    std::cout << "Voter processes tally phase - aggregates encrypted ballots, verifies voting result using decryption "
                 "proof..."
              << std::endl
              << std::endl;

    std::size_t tree_depth = 0;
    if (vm.count("tree-depth")) {
        tree_depth = vm["tree-depth"].as<std::size_t>();
    } else {
        std::cerr << "Tree depth is not specified!" << std::endl;
        return;
    }
    std::size_t participants_number = 1 << tree_depth;

    auto ct_agg = marshaling_policy::read_ct(vm, 0);
    for (auto proof_idx = 1; proof_idx < participants_number; proof_idx++) {
        auto ct_i = marshaling_policy::read_ct(vm, proof_idx);
        if (std::size(ct_agg) != std::size(ct_i)) {
            std::cerr << "Wrong size of the ct" << std::endl;
            std::exit(2);
        }
        for (std::size_t i = 0; i < std::size(ct_i); ++i) {
            ct_agg[i] = ct_agg[i] + ct_i[i];
        }
    }

    auto vk_eid = marshaling_policy::read_vk_eid(vm);
    typename enc_input_policy::proof_system::keypair_type gg_keypair = {marshaling_policy::read_pk_crs(vm),
                                                                        marshaling_policy::read_vk_crs(vm)};
    auto voting_result = marshaling_policy::read_scalar_vector(vm["voting-result-output"].as<std::string>());
    auto dec_proof = marshaling_policy::read_decryption_proof(vm);
    std::cout << "Verification of the deciphered tally result." << std::endl;
    bool dec_verification_ans = verify_decryption<enc_input_policy::encryption_scheme_type>(
        ct_agg, voting_result, {vk_eid, gg_keypair, dec_proof});
    if (!dec_verification_ans)
        std::exit(1);
    std::cout << "Verification succeeded" << std::endl;
    std::cout << "Results of voting:" << std::endl;
    for (std::size_t i = 0; i < enc_input_policy::msg_size; ++i) {
        std::cout << voting_result[i].data << ", ";
    }
    std::cout << std::endl;
}

int main(int argc, char *argv[]) {
    std::srand(std::time(0));

    std::string mode;
    std::size_t tree_depth;
    boost::program_options::options_description desc(
        "R1CS Generic Group PreProcessing Zero-Knowledge Succinct Non-interactive ARgument of Knowledge "
        "(https://eprint.iacr.org/2016/260.pdf) CLI Proof Generator.");
    // clang-format off
    desc.add_options()
    ("help,h", "Display help message.")
    ("version,v", "Display version.")
    ("mode,m", boost::program_options::value(&mode)->default_value("encrypted_input"),"Proof system processing mode, allowed values: basic, encrypted_input.")
    ("phase,p", boost::program_options::value<std::string>(),"Execute protocol phase, allowed values:\n\t - init_voter (generate and write voters public and secret keys),\n\t - init_admin (generate and write CRS and ElGamal keys),\n\t - vote (read CRS and ElGamal keys, encrypt ballot and generate proof, then write them),\n\t - vote_verify (read voters' proofs and encrypted ballots and verify them),\n\t - tally_admin (read voters' encrypted ballots, aggregate encrypted ballots, decrypt aggregated ballot and generate decryption proof and write them),\n\t - tally_voter (read ElGamal verification and public keys, encrypted ballots, decrypted aggregated ballot, decryption proof and verify them).")
    ("voter-idx,vidx", boost::program_options::value<std::size_t>()->default_value(0),"Voter index")
    ("voter-public-key-output,vpko", boost::program_options::value<std::string>()->default_value("voter_public_key"),"Voter public key")
    ("voter-secret-key-output,vsko", boost::program_options::value<std::string>()->default_value("voter_secret_key"),"Voter secret key")
    ("r1cs-proof-output,rpo", boost::program_options::value<std::string>()->default_value("r1cs_proof"), "Proof output path.")
    ("r1cs-primary-input-output,rpio", boost::program_options::value<std::string>()->default_value("r1cs_primary_input"), "Primary input output path.")
    ("r1cs-proving-key-output,rpko", boost::program_options::value<std::string>()->default_value("r1cs_proving_key"), "Proving key output path.")
    ("r1cs-verification-key-output,rvko", boost::program_options::value<std::string>()->default_value("r1cs_verification_key"), "Verification output path.")
    ("r1cs-verifier-input-output,rvio", boost::program_options::value<std::string>()->default_value("r1cs_verification_input"), "Verification input output path.")
    ("public-key-output,pko", boost::program_options::value<std::string>()->default_value("pk_eid"), "Public key output path (for encrypted_input mode only).")
    ("verification-key-output,vko", boost::program_options::value<std::string>()->default_value("vk_eid"), "Verification key output path (for encrypted_input mode only).")
    ("secret-key-output,sko", boost::program_options::value<std::string>()->default_value("sk_eid"), "Secret key output path (for encrypted_input mode only).")
    ("cipher-text-output,cto", boost::program_options::value<std::string>()->default_value("cipher_text"), "Cipher text output path (for encrypted_input mode only).")
    ("decryption-proof-output,dpo", boost::program_options::value<std::string>()->default_value("decryption_proof"), "Decryption proof output path (for encrypted_input mode only).")
    ("voting-result-output,vro", boost::program_options::value<std::string>()->default_value("voting_result"), "Voting result output path (for encrypted_input mode only).")
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
        using curve_type = algebra::curves::bls12<381>;
        using scalar_field_type = typename curve_type::scalar_field_type;
        using endianness = nil::marshalling::option::big_endian;
        using proof_system_type = zk::snark::r1cs_gg_ppzksnark<curve_type>;

        process_basic_mode<curve_type, endianness, proof_system_type>(vm);
    } else if (vm["mode"].as<std::string>() == "encrypted_input") {
        if (!vm.count("phase")) {
            process_encrypted_input_mode(vm);
        } else {
            if (vm["phase"].as<std::string>() == "init_voter") {
                process_encrypted_input_mode_init_voter_phase(vm);
            } else if (vm["phase"].as<std::string>() == "init_admin") {
                process_encrypted_input_mode_init_admin_phase(vm);
            } else if (vm["phase"].as<std::string>() == "vote") {
                process_encrypted_input_mode_vote_phase(vm);
            } else if (vm["phase"].as<std::string>() == "vote_verify") {
                process_encrypted_input_mode_vote_verify_phase(vm);
            } else if (vm["phase"].as<std::string>() == "tally_admin") {
                process_encrypted_input_mode_tally_admin_phase(vm);
            } else if (vm["phase"].as<std::string>() == "tally_voter") {
                process_encrypted_input_mode_tally_voter_phase(vm);
            } else {
                std::cout << desc << std::endl;
                return 0;
            }
        }
    } else {
        std::cout << desc << std::endl;
        return 0;
    }

    return 0;
}