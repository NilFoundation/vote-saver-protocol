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

#define BOOST_ENABLE_ASSERT_HANDLER
#include <boost/assert.hpp>

#include <iostream>
#include <filesystem>
#include <fstream>
#include <string>
#include <functional>
#include <ctime>

#include <boost/filesystem.hpp>
#include <boost/program_options.hpp>

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

#include <nil/crypto3/zk/algorithms/generate.hpp>
#include <nil/crypto3/zk/algorithms/verify.hpp>
#include <nil/crypto3/zk/algorithms/prove.hpp>

#include <nil/marshalling/status_type.hpp>
#include <nil/crypto3/marshalling/zk/types/r1cs_gg_ppzksnark/primary_input.hpp>
#include <nil/crypto3/marshalling/zk/types/r1cs_gg_ppzksnark/proof.hpp>
#include <nil/crypto3/marshalling/zk/types/r1cs_gg_ppzksnark/verification_key.hpp>
#include <nil/crypto3/marshalling/zk/types/r1cs_gg_ppzksnark/fast_proving_key.hpp>
#include <nil/crypto3/marshalling/pubkey/types/elgamal_verifiable.hpp>

#include <nil/crypto3/pubkey/algorithm/generate_keypair.hpp>
#include <nil/crypto3/pubkey/algorithm/encrypt.hpp>
#include <nil/crypto3/pubkey/algorithm/decrypt.hpp>
#include <nil/crypto3/pubkey/algorithm/verify_encryption.hpp>
#include <nil/crypto3/pubkey/algorithm/verify_decryption.hpp>
#include <nil/crypto3/pubkey/algorithm/rerandomize.hpp>
#include <nil/crypto3/pubkey/elgamal_verifiable.hpp>
#include <nil/crypto3/pubkey/modes/verifiable_encryption.hpp>

#include <nil/crypto3/random/algebraic_random_device.hpp>

#include <nil/crypto3/detail/pack.hpp>

using namespace nil::crypto3;
using namespace nil::crypto3::algebra;
using namespace nil::crypto3::pubkey;
using namespace nil::crypto3::marshalling;
using namespace nil::crypto3::zk;

template<typename TIter>
void print_byteblob(std::ostream &os, TIter iter_begin, TIter iter_end) {
    os << std::hex;
    for (TIter it = iter_begin; it != iter_end; it++) {
        os << std::setfill('0') << std::setw(2) << std::right << int(*it);
    }
    os << std::dec << std::endl;
}

template<typename FieldParams>
void print_field_element(std::ostream &os, const typename fields::detail::element_fp<FieldParams> &e,
                         bool endline = true) {
    os << e.data;
    if (endline) {
        os << std::endl;
    }
}

template<typename FieldParams>
void print_field_element(std::ostream &os, const typename fields::detail::element_fp2<FieldParams> &e,
                         bool endline = true) {
    os << e.data[0].data << ", " << e.data[1].data;
    if (endline) {
        os << std::endl;
    }
}

template<typename CurveParams, typename Form, typename Coordinates>
typename std::enable_if<std::is_same<Coordinates, curves::coordinates::affine>::value>::type
print_curve_point(std::ostream &os, const curves::detail::curve_element<CurveParams, Form, Coordinates> &p) {
    os << "( X: [";
    print_field_element(os, p.X, false);
    os << "], Y: [";
    print_field_element(os, p.Y, false);
    os << "] )" << std::endl;
}

template<typename CurveParams, typename Form, typename Coordinates>
typename std::enable_if<std::is_same<Coordinates, curves::coordinates::projective>::value ||
                        std::is_same<Coordinates, curves::coordinates::jacobian_with_a4_0>::value ||
                        std::is_same<Coordinates, curves::coordinates::inverted>::value>::type
print_curve_point(std::ostream &os, const curves::detail::curve_element<CurveParams, Form, Coordinates> &p) {
    os << "( X: [";
    print_field_element(os, p.X, false);
    os << "], Y: [";
    print_field_element(os, p.Y, false);
    os << "], Z:[";
    print_field_element(os, p.Z, false);
    os << "] )" << std::endl;
}

// #define DISABLE_OUTPUT

template<typename ...Args>
inline void log(Args && ...args)
{
#ifndef DISABLE_OUTPUT
    (std::cout<< ... << args);
#endif
}

template<typename ...Args>
inline void logln(Args && ...args)
{
#ifndef DISABLE_OUTPUT
    (std::cout << ... << args) << std::endl;
#endif
}

struct encrypted_input_policy {
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
    using voting_component =
    components::encrypted_input_voting<arity, hash_component, merkle_hash_component, field_type>;
    using merkle_proof_component = typename voting_component::merkle_proof_component;
    using encryption_scheme_type = elgamal_verifiable<pairing_curve_type>;
    using proof_system = typename encryption_scheme_type::proof_system_type;
    static constexpr std::size_t msg_size = 25;
    static constexpr std::size_t secret_key_bits = hash_type::digest_bits;
    static constexpr std::size_t public_key_bits = secret_key_bits;
};

struct marshaling_policy {
    using scalar_field_value_type =
    typename encrypted_input_policy::encryption_scheme_type::curve_type::scalar_field_type::value_type;
    using proof_type = typename encrypted_input_policy::proof_system::proof_type;
    using verification_key_type = typename encrypted_input_policy::proof_system::verification_key_type;
    using proving_key_type = typename encrypted_input_policy::proof_system::proving_key_type;
    using primary_input_type = typename encrypted_input_policy::proof_system::primary_input_type;
    using elgamal_public_key_type = typename encrypted_input_policy::encryption_scheme_type::public_key_type;
    using elgamal_private_key_type = typename encrypted_input_policy::encryption_scheme_type::private_key_type;
    using elgamal_verification_key_type =
    typename encrypted_input_policy::encryption_scheme_type::verification_key_type;

    using endianness = nil::marshalling::option::big_endian;
    using r1cs_proof_marshaling_type =
    nil::crypto3::marshalling::types::r1cs_gg_ppzksnark_proof<nil::marshalling::field_type<endianness>, proof_type>;
    using r1cs_verification_key_marshaling_type =
    nil::crypto3::marshalling::types::r1cs_gg_ppzksnark_extended_verification_key<
    nil::marshalling::field_type<endianness>, verification_key_type>;
    using r1cs_proving_key_marshalling_type =
    nil::crypto3::marshalling::types::r1cs_gg_ppzksnark_fast_proving_key<nil::marshalling::field_type<endianness>,
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
    nil::marshalling::field_type<endianness>,
    encrypted_input_policy::encryption_scheme_type::cipher_type::first_type>;
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
        BOOST_ASSERT_MSG(
                std::filesystem::exists(path),
                (std::string("File ") + path + std::string(" doesn't exist, make sure you created it!")).c_str());
        std::ifstream in(path, std::ios_base::binary);
        std::stringstream buffer;
        buffer << in.rdbuf();
        auto blob_str = buffer.str();
        return {std::cbegin(blob_str), std::cend(blob_str)};
    }

    static void write_initial_phase_voter_data(const std::array<bool, encrypted_input_policy::public_key_bits> &voter_pubkey,
                                               const std::array<bool, encrypted_input_policy::secret_key_bits> &voter_skey, std::size_t i,
                                               const std::string &voter_pk_out, const std::string &voter_sk_out) {
        std::vector<std::uint8_t> pubkey_blob;
        std::vector<std::uint8_t> sk_blob;

        serialize_initial_phase_voter_data(voter_pubkey, voter_skey, pubkey_blob, sk_blob);

        if (!voter_pk_out.empty()) {
            auto filename = voter_pk_out + std::to_string(i) + ".bin";
            write_obj(std::filesystem::path(filename), {pubkey_blob});
        }

        if (!voter_sk_out.empty()) {
            auto filename = voter_sk_out + std::to_string(i) + ".bin";
            write_obj(std::filesystem::path(filename), {sk_blob});
        }
    }

    static void serialize_initial_phase_voter_data(const std::array<bool, encrypted_input_policy::public_key_bits> &voter_pubkey,
                                                   const std::array<bool, encrypted_input_policy::secret_key_bits> &voter_skey,
                                                   std::vector<std::uint8_t> &voter_pk_out,
                                                   std::vector<std::uint8_t> &voter_sk_out) {
        voter_pk_out = serialize_bitarray<encrypted_input_policy::public_key_bits>(voter_pubkey);
        voter_sk_out = serialize_bitarray<encrypted_input_policy::secret_key_bits>(voter_skey);
    }

    static void write_initial_phase_admin_data(
            const proving_key_type &pk_crs, const verification_key_type &vk_crs, const elgamal_public_key_type &pk_eid,
            const elgamal_private_key_type &sk_eid, const elgamal_verification_key_type &vk_eid,
            const primary_input_type &eid, const primary_input_type &rt, const std::vector<std::array<bool, encrypted_input_policy::merkle_hash_type::digest_bits>> hashes,
            const std::string &r1cs_proving_key_out,
            const std::string &r1cs_verification_key_out, const std::string &public_key_output,
            const std::string &secret_key_output, const std::string &verification_key_output, const std::string &eid_output,
            const std::string &rt_output) {

        std::vector<std::uint8_t> pk_crs_blob;
        std::vector<std::uint8_t> vk_crs_blob;
        std::vector<std::uint8_t> pk_eid_blob;
        std::vector<std::uint8_t> sk_eid_blob;
        std::vector<std::uint8_t> vk_eid_blob;
        std::vector<std::uint8_t> eid_blob;
        std::vector<std::uint8_t> rt_blob;
        std::vector<std::uint8_t> merkle_tree_blob;

        serialize_initial_phase_admin_keys(pk_crs, vk_crs, pk_eid, sk_eid, vk_eid,
                                           pk_crs_blob, vk_crs_blob,
                                           pk_eid_blob, sk_eid_blob, vk_eid_blob);
        serialize_initial_phase_admin_data(eid, rt, hashes,
                                           eid_blob, rt_blob, merkle_tree_blob);

        if (!r1cs_proving_key_out.empty()) {
            auto filename = r1cs_proving_key_out + ".bin";
            write_obj(std::filesystem::path(filename), {pk_crs_blob});
        }

        if (!r1cs_verification_key_out.empty()) {
            auto filename = r1cs_verification_key_out + ".bin";
            write_obj(std::filesystem::path(filename), {vk_crs_blob});
        }

        if (!public_key_output.empty()) {
            auto filename = public_key_output + ".bin";
            write_obj(std::filesystem::path(filename), {pk_eid_blob});
        }

        if (!secret_key_output.empty()) {
            auto filename = secret_key_output + ".bin";
            write_obj(std::filesystem::path(filename), {sk_eid_blob});
        }

        if (!verification_key_output.empty()) {
            auto filename = verification_key_output + ".bin";
            write_obj(std::filesystem::path(filename), {vk_eid_blob});
        }

        if (!eid_output.empty()) {
            auto filename = eid_output + ".bin";
            write_obj(std::filesystem::path(filename), {eid_blob});
        }

        if (!rt_output.empty()) {
            auto filename = rt_output + ".bin";
            write_obj(std::filesystem::path(filename), {rt_blob});
        }
    }


    static void serialize_initial_phase_admin_keys(const proving_key_type &pk_crs, const verification_key_type &vk_crs,
            const elgamal_public_key_type &pk_eid,
            const elgamal_private_key_type &sk_eid, const elgamal_verification_key_type &vk_eid,
            std::vector<std::uint8_t> &r1cs_proving_key_out,
            std::vector<std::uint8_t> &r1cs_verification_key_out, std::vector<std::uint8_t> &public_key_output,
            std::vector<std::uint8_t> &secret_key_output, std::vector<std::uint8_t> &verification_key_output) {
        r1cs_proving_key_out = serialize_obj<r1cs_proving_key_marshalling_type>(
                pk_crs,
                std::function(
                        nil::crypto3::marshalling::types::fill_r1cs_gg_ppzksnark_fast_proving_key<proving_key_type, endianness>));

        r1cs_verification_key_out = serialize_obj<r1cs_verification_key_marshaling_type>(
                vk_crs,
                std::function(
                        nil::crypto3::marshalling::types::fill_r1cs_gg_ppzksnark_verification_key<verification_key_type,
                        endianness>));

        public_key_output = serialize_obj<public_key_marshaling_type>(
                pk_eid,
                std::function(nil::crypto3::marshalling::types::fill_public_key<elgamal_public_key_type, endianness>));

        secret_key_output = serialize_obj<secret_key_marshaling_type>(
                sk_eid,
                std::function(nil::crypto3::marshalling::types::fill_private_key<elgamal_private_key_type, endianness>));

        verification_key_output = serialize_obj<verification_key_marshaling_type>(
                vk_eid,
                std::function(
                        nil::crypto3::marshalling::types::fill_verification_key<elgamal_verification_key_type, endianness>));
    }

    static void serialize_initial_phase_admin_data(
            const primary_input_type &eid, const primary_input_type &rt,
            const std::vector<std::array<bool, encrypted_input_policy::merkle_hash_type::digest_bits>> &merkle_tree_hashes,
            std::vector<std::uint8_t> &eid_output, std::vector<std::uint8_t> &rt_output,
            std::vector<std::uint8_t> &merkle_tree_output) {        
        eid_output = serialize_obj<pinput_marshaling_type>(
                eid,
                std::function(nil::crypto3::marshalling::types::fill_r1cs_gg_ppzksnark_primary_input<primary_input_type,
                              endianness>));

        rt_output = serialize_obj<pinput_marshaling_type>(
                rt,
                std::function(nil::crypto3::marshalling::types::fill_r1cs_gg_ppzksnark_primary_input<primary_input_type,
                              endianness>));
        for(auto hash : merkle_tree_hashes){
            auto hash_blob = serialize_bitarray<encrypted_input_policy::merkle_hash_type::digest_bits>(hash);
            merkle_tree_output.insert(merkle_tree_output.end(), hash_blob.begin(), hash_blob.end());
        }
    }

    static void write_data(std::size_t proof_idx, const boost::program_options::variables_map &vm,
                           const verification_key_type &vk_crs, const elgamal_public_key_type &pk_eid,
                           const proof_type &proof, const primary_input_type &pinput,
                           const encrypted_input_policy::encryption_scheme_type::cipher_type::first_type &ct,
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
                              encrypted_input_policy::encryption_scheme_type::cipher_type::first_type, endianness>));
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

    static void serialize_data(std::size_t proof_idx, const proof_type &proof,
                               const primary_input_type &pinput,
                               const encrypted_input_policy::encryption_scheme_type::cipher_type::first_type &ct,
                               const primary_input_type &sn,
                               std::vector<std::uint8_t> &proof_blob,
                               std::vector<std::uint8_t> &pinput_blob, std::vector<std::uint8_t> &ct_blob,
                               std::vector<std::uint8_t> &sn_blob) {
        proof_blob = serialize_obj<r1cs_proof_marshaling_type>(
                proof,
                std::function(nil::crypto3::marshalling::types::fill_r1cs_gg_ppzksnark_proof<proof_type, endianness>));

        pinput_blob = serialize_obj<pinput_marshaling_type>(
                pinput,
                std::function(nil::crypto3::marshalling::types::fill_r1cs_gg_ppzksnark_primary_input<primary_input_type,
                              endianness>));

        ct_blob = serialize_obj<ct_marshaling_type>(
                ct,
                std::function(nil::crypto3::marshalling::types::fill_r1cs_gg_ppzksnark_encrypted_primary_input<
                              encrypted_input_policy::encryption_scheme_type::cipher_type::first_type, endianness>));

        sn_blob = serialize_obj<pinput_marshaling_type>(
                sn,
                std::function(nil::crypto3::marshalling::types::fill_r1cs_gg_ppzksnark_primary_input<primary_input_type,
                              endianness>));
    }

    static void
    write_tally_phase_data(const boost::program_options::variables_map &vm,
                           const typename encrypted_input_policy::encryption_scheme_type::decipher_type &dec) {
        nil::marshalling::status_type status;
        std::vector<std::uint8_t> dec_proof_blob = nil::marshalling::pack<endianness>(dec.second, status);
        if (vm.count("decryption-proof-output")) {
            auto filename = vm["decryption-proof-output"].as<std::string>() + ".bin";
            write_obj(filename, {
                    dec_proof_blob,
            });
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

    static void
    serialize_tally_phase_data(const typename encrypted_input_policy::encryption_scheme_type::decipher_type &dec,
                               std::vector<std::uint8_t> &dec_proof_blob,
                               std::vector<std::uint8_t> &voting_res_blob) {
        nil::marshalling::status_type status;
        dec_proof_blob = static_cast<std::vector<std::uint8_t>>(nil::marshalling::pack<endianness>(dec.second, status));

        voting_res_blob = serialize_obj<pinput_marshaling_type>(
                dec.first,
                std::function(nil::crypto3::marshalling::types::fill_r1cs_gg_ppzksnark_primary_input<
                              std::vector<scalar_field_value_type>, endianness>));
    }

    static std::vector<scalar_field_value_type> read_scalar_vector(const std::string &file_prefix) {
        auto filename = file_prefix + ".bin";
        return deserialize_scalar_vector(read_obj(filename));
    }

    static std::vector<scalar_field_value_type> deserialize_scalar_vector(const std::vector<std::uint8_t> &blob) {
        return deserialize_obj<pinput_marshaling_type, std::vector<scalar_field_value_type>>(
                blob,
                        std::function(nil::crypto3::marshalling::types::make_r1cs_gg_ppzksnark_primary_input<
                                      std::vector<scalar_field_value_type>, endianness>));
    }

    static std::vector<bool> read_bool_vector(const std::string &file_prefix) {
        auto filename = file_prefix + ".bin";
        return deserialize_bool_vector(read_obj(filename));
    }

    static std::vector<bool> deserialize_bool_vector(const std::vector<std::uint8_t> &blob) {
        std::vector<bool> result;
        for (const auto &i : deserialize_scalar_vector(blob)) {
            result.emplace_back(i.data);
        }
        return result;
    }

    static scalar_field_value_type get_field_element_from_bits(const std::vector<bool> &bits) {
        BOOST_ASSERT(bits.size() < encrypted_input_policy::field_type::value_bits);
        scalar_field_value_type result = scalar_field_value_type::zero();

        for (std::size_t i = 0; i < bits.size(); ++i) {
            /* push in the new bit */
            const scalar_field_value_type v = (bits[bits.size() - 1 - i] ?
                                               scalar_field_value_type::one() :
                                               scalar_field_value_type::zero());
            result = result + (result + v);
        }

        return result;
    }

    static std::vector<scalar_field_value_type> get_multi_field_element_from_bits(const std::vector<bool> &bits) {
        std::vector<scalar_field_value_type> result;
        const std::size_t chunk_size = encrypted_input_policy::field_type::value_bits - 1;
        for (std::size_t i = 0; i < bits.size(); i+=chunk_size) {
            std::vector<bool> field_bits(bits.begin()+i, bits.begin() + std::min(i + chunk_size, bits.size()));
            /* push in the new bit */
            const scalar_field_value_type v = get_field_element_from_bits(field_bits);
            result.emplace_back(v);
        }

        return result;
    }

    template<int bits>
    static std::vector<std::uint8_t> serialize_bitarray(const std::array<bool, bits> &bitarray) {

        constexpr int octets = bits/8 + (bits%8 ? 1 : 0);
        constexpr int bits_ceil = octets*8;

        std::array<std::uint8_t, bits_ceil> in {};
        std::copy_n(bitarray.begin(), bits, in.begin());

        std::array<std::uint8_t, octets> out {};
        nil::crypto3::detail::pack<nil::crypto3::stream_endian::big_octet_big_bit, nil::crypto3::stream_endian::big_octet_big_bit, 1, 8>(in.begin(), in.end(), out.begin());

        std::vector<std::uint8_t> res;
        std::copy(out.begin(), out.end(), std::back_inserter(res));

        return res;
    }

    template<int bits>
    static std::array<bool, bits> deserialize_bitarray(const std::vector<std::uint8_t>::const_iterator &begin, const std::vector<std::uint8_t>::const_iterator &end) {
        constexpr int octets = bits/8 + (bits%8 ? 1 : 0);
        constexpr int bits_ceil = octets*8;

        std::array<std::uint8_t, octets> in {};
        BOOST_ASSERT(std::distance(begin, end) == octets);
        std::copy_n(begin, octets, in.begin());

        std::array<bool, bits_ceil> out {};
        nil::crypto3::detail::pack<nil::crypto3::stream_endian::big_octet_big_bit, nil::crypto3::stream_endian::big_octet_big_bit, 8, 1>(in.begin(), in.end(), out.begin());

        std::array<bool, bits> res;
        std::copy_n(out.begin(), bits, res.begin());

        return res;
    }

    template<int bits>
    static std::array<bool, bits> deserialize_bitarray(const std::vector<std::uint8_t> &blob) {

        return deserialize_bitarray<bits>(blob.begin(), blob.end());
    }

    static containers::merkle_tree<encrypted_input_policy::merkle_hash_type, encrypted_input_policy::arity>
    deserialize_merkle_tree(std::size_t tree_depth, std::vector<std::uint8_t> merkle_tree_blob) {
        std::size_t tree_length = containers::detail::merkle_tree_length(1 << tree_depth, encrypted_input_policy::arity);
        BOOST_ASSERT(merkle_tree_blob.size() % tree_length == 0);
        std::size_t hash_octets = merkle_tree_blob.size() / tree_length;

        std::vector<std::vector<bool>> hashes;
        hashes.reserve(tree_length);

        for(auto iter = merkle_tree_blob.begin(); iter < merkle_tree_blob.end(); iter += hash_octets) {
            auto array = deserialize_bitarray<encrypted_input_policy::merkle_hash_type::digest_bits>(iter, iter + hash_octets);
            hashes.emplace_back(array.begin(), array.end());
        }
        BOOST_ASSERT(hashes.size() == tree_length);

        return containers::merkle_tree<encrypted_input_policy::merkle_hash_type, encrypted_input_policy::arity>(1 << tree_depth, hashes.begin(), hashes.end());
    }

    static std::vector<std::vector<std::uint8_t>> read_voters_public_keys_blobs(std::size_t tree_depth,
                                                                                                          const std::string &voter_public_key_output) {
        std::size_t participants_number = 1 << tree_depth;
        std::vector<std::vector<std::uint8_t>> blobs;

        for (auto i = 0; i < participants_number; i++) {
            if (!voter_public_key_output.empty()) {
                blobs.emplace_back(read_obj(voter_public_key_output + std::to_string(i) + ".bin"));
            }
        }
        return blobs;
    }

    static std::vector<std::array<bool, encrypted_input_policy::public_key_bits>> read_voters_public_keys(std::size_t tree_depth,
                                                                                                          const std::string &voter_public_key_output) {
        auto blobs = read_voters_public_keys_blobs(tree_depth, voter_public_key_output);
        return deserialize_voters_public_keys(tree_depth, blobs);
    }

    static std::vector<std::array<bool, encrypted_input_policy::public_key_bits>>
    deserialize_voters_public_keys(std::size_t tree_depth, const std::vector<std::vector<std::uint8_t>> &blobs) {
        std::size_t participants_number = 1 << tree_depth;
        BOOST_ASSERT(blobs.size() <= participants_number);
        std::vector<std::array<bool, encrypted_input_policy::public_key_bits>> result;

        for (auto i = 0; i < blobs.size(); i++) {
            result.emplace_back(deserialize_bitarray<encrypted_input_policy::public_key_bits>(blobs[i]));
        }

        for (auto i = blobs.size(); i < participants_number; i++) {
            result.emplace_back(
                    std::array<bool, encrypted_input_policy::public_key_bits> {}
            );
        }

        return result;
    }

    static elgamal_public_key_type read_pk_eid(const boost::program_options::variables_map &vm) {
        auto pk_eid_blob = read_obj(vm["public-key-output"].as<std::string>() + ".bin");
        return deserialize_obj<public_key_marshaling_type, elgamal_public_key_type>(
                pk_eid_blob,
                std::function(nil::crypto3::marshalling::types::make_public_key<elgamal_public_key_type, endianness>));
    }

    static elgamal_public_key_type deserialize_pk_eid(const std::vector<std::uint8_t> &pk_eid_blob) {
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

    static elgamal_verification_key_type deserialize_vk_eid(const std::vector<std::uint8_t> &vk_eid_blob) {
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

    static elgamal_private_key_type deserialize_sk_eid(const std::vector<std::uint8_t> &sk_eid_blob) {
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

    static verification_key_type deserialize_vk_crs(const std::vector<std::uint8_t> &vk_crs_blob) {
        return deserialize_obj<r1cs_verification_key_marshaling_type, verification_key_type>(
                vk_crs_blob, std::function(nil::crypto3::marshalling::types::make_r1cs_gg_ppzksnark_verification_key<
                                           verification_key_type, endianness>));
    }

    static proving_key_type read_pk_crs(const boost::program_options::variables_map &vm) {
        auto pk_crs_blob = read_obj(vm["r1cs-proving-key-output"].as<std::string>() + ".bin");
        return deserialize_obj<r1cs_proving_key_marshalling_type, proving_key_type>(
                pk_crs_blob,
                std::function(
                        nil::crypto3::marshalling::types::make_r1cs_gg_ppzksnark_fast_proving_key<proving_key_type, endianness>));
    }

    static proving_key_type deserialize_pk_crs(const std::vector<std::uint8_t> &pk_crs_blob) {
        return deserialize_obj<r1cs_proving_key_marshalling_type, proving_key_type>(
                pk_crs_blob,
                std::function(
                        nil::crypto3::marshalling::types::make_r1cs_gg_ppzksnark_fast_proving_key<proving_key_type, endianness>));
    }

    static proof_type read_proof(const boost::program_options::variables_map &vm, std::size_t proof_idx) {
        auto proof_blob = read_obj(vm["r1cs-proof-output"].as<std::string>() + std::to_string(proof_idx) + ".bin");
        return deserialize_obj<r1cs_proof_marshaling_type, proof_type>(
                proof_blob,
                std::function(nil::crypto3::marshalling::types::make_r1cs_gg_ppzksnark_proof<proof_type, endianness>));
    }

    static typename encrypted_input_policy::encryption_scheme_type::cipher_type::first_type
    read_ct(const boost::program_options::variables_map &vm, std::size_t proof_idx) {
        return deserialize_obj<ct_marshaling_type,
                typename encrypted_input_policy::encryption_scheme_type::cipher_type::first_type>(
                read_obj(vm["cipher-text-output"].as<std::string>() + std::to_string(proof_idx) + ".bin"),
                std::function(
                        nil::crypto3::marshalling::types::make_r1cs_gg_ppzksnark_encrypted_primary_input<
                        typename encrypted_input_policy::encryption_scheme_type::cipher_type::first_type, endianness>));
    }

    static typename encrypted_input_policy::encryption_scheme_type::cipher_type::first_type
    deserialize_ct(const std::vector<std::uint8_t> &blob) {
        return deserialize_obj<ct_marshaling_type,
                typename encrypted_input_policy::encryption_scheme_type::cipher_type::first_type>(
                blob,
                std::function(
                        nil::crypto3::marshalling::types::make_r1cs_gg_ppzksnark_encrypted_primary_input<
                        typename encrypted_input_policy::encryption_scheme_type::cipher_type::first_type, endianness>));
    }

    static typename encrypted_input_policy::encryption_scheme_type::decipher_type::second_type
    read_decryption_proof(const boost::program_options::variables_map &vm) {
        auto dec_proof_blob = read_obj(vm["decryption-proof-output"].as<std::string>() + ".bin");
        nil::marshalling::status_type status;
        return static_cast<typename encrypted_input_policy::encryption_scheme_type::decipher_type::second_type>(
                nil::marshalling::pack<endianness>(dec_proof_blob, status));
    }

    static typename encrypted_input_policy::encryption_scheme_type::decipher_type::second_type
    deserialize_decryption_proof(const std::vector<std::uint8_t> &dec_proof_blob) {
        nil::marshalling::status_type status;
        return static_cast<typename encrypted_input_policy::encryption_scheme_type::decipher_type::second_type>(
                nil::marshalling::pack<endianness>(dec_proof_blob, status));
    }
};

bool did_srand = false;

void srand_once() {
    if(!did_srand) {
        did_srand = true;
        std::srand(std::time(0));
    }
}

template<typename ValueType, std::size_t N>
typename std::enable_if<std::is_unsigned<ValueType>::value, std::vector<std::array<ValueType, N>>>::type
generate_random_data(std::size_t leaf_number) {
    std::vector<std::array<ValueType, N>> v;
    srand_once();
    for (std::size_t i = 0; i < leaf_number; ++i) {
        std::array<ValueType, N> leaf {};
        std::generate(std::begin(leaf), std::end(leaf),
                      [&]() { return std::rand() % (std::numeric_limits<ValueType>::max() + 1); });
        v.emplace_back(leaf);
    }
    return v;
}

void process_encrypted_input_mode_init_voter_phase(std::size_t voter_idx, std::vector<std::uint8_t> &voter_pk_out,
                                                   std::vector<std::uint8_t> &voter_sk_out) {
    using scalar_field_value_type = typename encrypted_input_policy::pairing_curve_type::scalar_field_type::value_type;

    std::size_t proof_idx = voter_idx;
    logln("Voter " , proof_idx , " generates its public and secret keys..." , "\n");
    auto secret_keys = generate_random_data<bool, encrypted_input_policy::secret_key_bits>(1);
    std::vector<std::array<bool, encrypted_input_policy::public_key_bits>> public_keys;
    std::array<bool, encrypted_input_policy::public_key_bits> pk {};
    hash<encrypted_input_policy::merkle_hash_type>(secret_keys[0], std::begin(pk));
    public_keys.emplace_back(pk);

    log("Public key of the Voter " , proof_idx , ": ");
    for (auto c : pk) {
        log(int(c));
    }

    logln();
    logln("Participants key pairs generated." );

    logln("Voter " , proof_idx , " keypair marshalling started..." );
    marshaling_policy::serialize_initial_phase_voter_data(pk, secret_keys[0], voter_pk_out, voter_sk_out);
    logln("Marshalling finished." );
}

void process_encrypted_input_mode_init_admin_phase_generate_keys(
    std::size_t tree_depth,  std::size_t eid_bits,
    std::vector<std::uint8_t> &r1cs_proving_key_out, std::vector<std::uint8_t> &r1cs_verification_key_out,
    std::vector<std::uint8_t> &public_key_output, std::vector<std::uint8_t> &secret_key_output,
    std::vector<std::uint8_t> &verification_key_output
) {
    using scalar_field_value_type = typename encrypted_input_policy::pairing_curve_type::scalar_field_type::value_type;

    logln("Voting system administrator generates R1CS..." );
    components::blueprint<encrypted_input_policy::field_type> bp;
    components::block_variable<encrypted_input_policy::field_type> m_block(bp, encrypted_input_policy::msg_size);

    std::size_t chunk_size = encrypted_input_policy::field_type::value_bits - 1;

    components::blueprint_variable_vector<encrypted_input_policy::field_type> eid_packed;
    std::size_t eid_packed_size = (eid_bits + (chunk_size - 1)) / chunk_size;
    eid_packed.allocate(bp, eid_packed_size);

    components::blueprint_variable_vector<encrypted_input_policy::field_type> sn_packed;
    std::size_t sn_packed_size = (encrypted_input_policy::hash_component::digest_bits + (chunk_size - 1)) / chunk_size;
    sn_packed.allocate(bp, sn_packed_size);

    components::blueprint_variable_vector<encrypted_input_policy::field_type> root_packed;
    std::size_t root_packed_size = (encrypted_input_policy::hash_component::digest_bits + (chunk_size - 1)) / chunk_size;
    root_packed.allocate(bp, root_packed_size);

    std::size_t primary_input_size = bp.num_variables();

    components::block_variable<encrypted_input_policy::field_type> eid_block(bp, eid_bits);
    components::digest_variable<encrypted_input_policy::field_type> sn_digest(
            bp, encrypted_input_policy::hash_component::digest_bits);
    components::digest_variable<encrypted_input_policy::field_type> root_digest(
            bp, encrypted_input_policy::merkle_hash_component::digest_bits);
    logln("Variables number in the generated R1CS: " , bp.num_variables() );

    components::multipacking_component<encrypted_input_policy::field_type> eid_packer(bp, eid_block.bits, eid_packed, chunk_size);
    components::multipacking_component<encrypted_input_policy::field_type> sn_packer(bp, sn_digest.bits, sn_packed, chunk_size);
    components::multipacking_component<encrypted_input_policy::field_type> root_packer(bp, root_digest.bits, root_packed, chunk_size);
    logln("Variables number in the generated R1CS: " , bp.num_variables() );

    components::blueprint_variable_vector<encrypted_input_policy::field_type> address_bits_va;
    address_bits_va.allocate(bp, tree_depth);
    encrypted_input_policy::merkle_proof_component path_var(bp, tree_depth);
    components::block_variable<encrypted_input_policy::field_type> sk_block(bp,
                                                                            encrypted_input_policy::secret_key_bits);
    logln("Variables number in the generated R1CS: " , bp.num_variables() );
    encrypted_input_policy::voting_component vote_var(
            bp, m_block, eid_block, sn_digest, root_digest, address_bits_va, path_var, sk_block,
            components::blueprint_variable<encrypted_input_policy::field_type>(0));
    logln("Variables number in the generated R1CS: " , bp.num_variables() );

    eid_packer.generate_r1cs_constraints(true);
    sn_packer.generate_r1cs_constraints(true);
    root_packer.generate_r1cs_constraints(true);

    path_var.generate_r1cs_constraints();
    vote_var.generate_r1cs_constraints();
    logln("R1CS generation finished." );
    logln("Constraints number in the generated R1CS: " , bp.num_constraints() );
    logln("Variables number in the generated R1CS: " , bp.num_variables() );
    bp.set_input_sizes(primary_input_size);

    logln("Administrator generates CRS..." );
    typename encrypted_input_policy::proof_system::keypair_type gg_keypair =
            nil::crypto3::zk::generate<encrypted_input_policy::proof_system>(bp.get_constraint_system());
    logln("CRS generation finished." );

    logln("Administrator generates private, public and verification keys for El-Gamal verifiable encryption "
          "scheme...");
    random::algebraic_random_device<typename encrypted_input_policy::pairing_curve_type::scalar_field_type> d;
    std::vector<scalar_field_value_type> rnd;
    for (std::size_t i = 0; i < encrypted_input_policy::msg_size * 3 + 2; ++i) {
        rnd.emplace_back(d());
    }
    typename encrypted_input_policy::encryption_scheme_type::keypair_type keypair =
            generate_keypair<encrypted_input_policy::encryption_scheme_type,
    modes::verifiable_encryption<encrypted_input_policy::encryption_scheme_type>>(
            rnd, {gg_keypair, encrypted_input_policy::msg_size});
    logln("Private, public and verification keys for El-Gamal verifiable encryption scheme generated.", "\n");
    logln("====================================================================" , "\n");

    logln("Administrator initial phase keys marshalling started..." );

    marshaling_policy::serialize_initial_phase_admin_keys(
    gg_keypair.first, gg_keypair.second, std::get<0>(keypair),
    std::get<1>(keypair), std::get<2>(keypair), r1cs_proving_key_out,
    r1cs_verification_key_out, public_key_output, secret_key_output,
    verification_key_output);
    logln("Marshalling finished." );
}

void process_encrypted_input_mode_init_admin_phase_generate_data(
        std::size_t tree_depth, std::size_t eid_bits, const std::vector<std::vector<std::uint8_t>> &public_keys_blobs,
        std::vector<std::uint8_t> &eid_output,
        std::vector<std::uint8_t> &rt_output, std::vector<std::uint8_t> &merkle_tree_output) {
    using scalar_field_value_type = typename encrypted_input_policy::pairing_curve_type::scalar_field_type::value_type;

    auto public_keys = marshaling_policy::deserialize_voters_public_keys(tree_depth, public_keys_blobs);
    logln("Finished deserialization of public keys" );

    logln("Administrator pre-initializes voting session..." , "\n");

    logln("Merkle tree generation upon participants public keys started..." );
    auto tree = containers::make_merkle_tree<encrypted_input_policy::merkle_hash_type, encrypted_input_policy::arity>(
            std::cbegin(public_keys), std::cend(public_keys));
    std::vector<scalar_field_value_type> rt_field = marshaling_policy::get_multi_field_element_from_bits(tree.root());
    logln("Merkle tree generation finished." );

    std::vector<bool> eid(eid_bits);
    srand_once();
    std::generate(eid.begin(), eid.end(), [&]() { return std::rand() % 2; });
    log("Voting session (eid) is: ");
    for (auto i : eid) {
        log(int(i));
    }
    logln();
    std::vector<scalar_field_value_type> eid_field = marshaling_policy::get_multi_field_element_from_bits(eid);

    std::vector<std::vector<bool>> hashes(tree.cbegin(), tree.cend());
    std::size_t hashes_size = hashes.size();
    std::vector<std::array<bool, encrypted_input_policy::merkle_hash_type::digest_bits>>
            hashes_array_vector(hashes_size, std::array<bool, encrypted_input_policy::merkle_hash_type::digest_bits> {});
    for(std::size_t i=0; i < hashes_size; ++i) {
        std::copy_n(hashes[i].begin(),
                    encrypted_input_policy::merkle_hash_type::digest_bits,
                    hashes_array_vector[i].begin());
    }
    logln("Administrator initial phase data marshalling started..." );
    marshaling_policy::serialize_initial_phase_admin_data(
            eid_field, rt_field, hashes_array_vector,
            eid_output, rt_output, merkle_tree_output);
    logln("Marshalling finished." );
}

// #define DEBUG_VERIFY_BALLOT

void process_encrypted_input_mode_vote_phase(
        std::size_t tree_depth, std::size_t eid_bits, std::size_t voter_idx, std::size_t vote, const std::vector<std::uint8_t> &merkle_tree_blob,
        const std::vector<std::uint8_t> &rt_blob,
        const std::vector<std::uint8_t> &eid_blob,
        const std::vector<std::uint8_t> &sk_blob,
        const std::vector<std::uint8_t> &pk_eid_blob,
        const std::vector<std::uint8_t> &proving_key_blob,
        const std::vector<std::uint8_t> &verification_key_blob,
        std::vector<std::uint8_t> &proof_blob, std::vector<std::uint8_t> &pinput_blob, std::vector<std::uint8_t> &ct_blob,
        std::vector<std::uint8_t> &sn_blob) {
    using scalar_field_value_type = typename encrypted_input_policy::pairing_curve_type::scalar_field_type::value_type;

    auto tree = marshaling_policy::deserialize_merkle_tree(tree_depth, merkle_tree_blob);
    auto admin_rt_field = marshaling_policy::deserialize_scalar_vector(rt_blob);
    auto eid_field = marshaling_policy::deserialize_scalar_vector(eid_blob);
    auto sk = marshaling_policy::deserialize_bitarray<encrypted_input_policy::secret_key_bits>(sk_blob);
    auto pk_eid = marshaling_policy::deserialize_pk_eid(pk_eid_blob);

    typename encrypted_input_policy::proof_system::keypair_type gg_keypair = {
            marshaling_policy::deserialize_pk_crs(proving_key_blob),
            marshaling_policy::deserialize_vk_crs(verification_key_blob)};

    logln("Finished deserialization of merkle_tree,rt,eid,sk,pk_eid,proving_key,verification_key");

    std::size_t participants_number = 1 << tree_depth;
    std::vector<bool> eid;
    eid.resize(eid_bits);
    std::size_t chunk_size = encrypted_input_policy::field_type::value_bits - 1;
    for(std::size_t i = 0; i < eid_bits; ++i) {
        eid[i] = nil::crypto3::multiprecision::bit_test(eid_field[i/chunk_size].data, i%chunk_size);
    }

    std::size_t proof_idx = voter_idx;
    BOOST_ASSERT_MSG(participants_number > proof_idx, "Voter index should be lass than number of participants!");

    logln("Voter " , proof_idx , " generate encrypted ballot" , "\n");

    logln("Voter with index " , proof_idx , " generates its merkle copath..." );
    std::vector<scalar_field_value_type> rt_field = marshaling_policy::get_multi_field_element_from_bits(tree.root());
    BOOST_ASSERT(rt_field == admin_rt_field);
    containers::merkle_proof<encrypted_input_policy::merkle_hash_type, encrypted_input_policy::arity> path(tree,
                                                                                                           proof_idx);
    logln("Copath generated." );
    auto tree_pk_leaf = tree[proof_idx];

    std::vector<bool> m(encrypted_input_policy::msg_size, false);
    m[vote] = true;
    log("Voter " , proof_idx , " is willing to vote with the following ballot: { ");
    for (auto m_i : m) {
        log(int(m_i));
    }
    logln(" }" );
    std::vector<typename encrypted_input_policy::pairing_curve_type::scalar_field_type::value_type> m_field;
    m_field.reserve(m.size());
    for (const auto m_i : m) {
        m_field.emplace_back(std::size_t(m_i));
    }

    std::vector<bool> eid_sk;
    std::copy(std::cbegin(eid), std::cend(eid), std::back_inserter(eid_sk));
    std::copy(std::cbegin(sk), std::cend(sk), std::back_inserter(eid_sk));
    std::vector<bool> sn = hash<encrypted_input_policy::hash_type>(eid_sk);
    log("Sender has following serial number (sn) in current session: ");
    for (auto i : sn) {
        log(int(i));
    }
    logln();

    components::blueprint<encrypted_input_policy::field_type> bp;
    components::block_variable<encrypted_input_policy::field_type> m_block(bp, encrypted_input_policy::msg_size);

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
    logln("Variables number in the generated R1CS: " , bp.num_variables() );

    components::multipacking_component<encrypted_input_policy::field_type> eid_packer(bp, eid_block.bits, eid_packed, chunk_size);
    components::multipacking_component<encrypted_input_policy::field_type> sn_packer(bp, sn_digest.bits, sn_packed, chunk_size);
    components::multipacking_component<encrypted_input_policy::field_type> root_packer(bp, root_digest.bits, root_packed, chunk_size);
    logln("Variables number in the generated R1CS: " , bp.num_variables() );

    components::blueprint_variable_vector<encrypted_input_policy::field_type> address_bits_va;
    address_bits_va.allocate(bp, tree_depth);
    encrypted_input_policy::merkle_proof_component path_var(bp, tree_depth);
    components::block_variable<encrypted_input_policy::field_type> sk_block(bp,
                                                                            encrypted_input_policy::secret_key_bits);
    logln("Variables number in the generated R1CS: " , bp.num_variables() );
    encrypted_input_policy::voting_component vote_var(
            bp, m_block, eid_block, sn_digest, root_digest, address_bits_va, path_var, sk_block,
            components::blueprint_variable<encrypted_input_policy::field_type>(0));
    logln("Variables number in the generated R1CS: " , bp.num_variables() );

    eid_packer.generate_r1cs_constraints(true);
    sn_packer.generate_r1cs_constraints(true);
    root_packer.generate_r1cs_constraints(true);

    path_var.generate_r1cs_constraints();
    vote_var.generate_r1cs_constraints();
    logln("R1CS generation finished." );
    logln("Constraints number in the generated R1CS: " , bp.num_constraints() );
    logln("Variables number in the generated R1CS: " , bp.num_variables() );
    bp.set_input_sizes(primary_input_size);

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
    sk_block.generate_r1cs_witness(sk);
    BOOST_ASSERT(!bp.is_satisfied());
    vote_var.generate_r1cs_witness(tree.root(), sn);
    BOOST_ASSERT(!bp.is_satisfied());
    eid_packer.generate_r1cs_witness_from_bits();
    BOOST_ASSERT(!bp.is_satisfied());
    root_packer.generate_r1cs_witness_from_bits();
    BOOST_ASSERT(!bp.is_satisfied());
    sn_packer.generate_r1cs_witness_from_bits();
    BOOST_ASSERT(bp.is_satisfied());

    logln("Voter " , proof_idx , " generates its vote consisting of proof and cipher text..." );
    random::algebraic_random_device<typename encrypted_input_policy::pairing_curve_type::scalar_field_type> d;
    typename encrypted_input_policy::encryption_scheme_type::cipher_type cipher_text =
            encrypt<encrypted_input_policy::encryption_scheme_type,
    modes::verifiable_encryption<encrypted_input_policy::encryption_scheme_type>>(
            m_field, {d(), pk_eid, gg_keypair, bp.primary_input(), bp.auxiliary_input()});
    logln("Vote generated." );

    logln("Rerandomization of the cipher text and proof started..." );
    std::vector<typename encrypted_input_policy::pairing_curve_type::scalar_field_type::value_type> rnd_rerandomization;
    for (std::size_t i = 0; i < 3; ++i) {
        rnd_rerandomization.emplace_back(d());
    }
    typename encrypted_input_policy::encryption_scheme_type::cipher_type rerand_cipher_text =
            rerandomize<encrypted_input_policy::encryption_scheme_type>(rnd_rerandomization, cipher_text.first,
                                                                        {pk_eid, gg_keypair, cipher_text.second});
    logln("Rerandomization finished." );

    logln("Voter " , proof_idx , " marshalling started..." );
    std::size_t eid_offset = m.size();
    std::size_t sn_offset = eid_offset + eid_packed.size();
    std::size_t rt_offset = sn_offset + sn_packed.size();
    std::size_t rt_offset_end = rt_offset + root_packed.size();
    typename encrypted_input_policy::proof_system::primary_input_type pinput = bp.primary_input();
    marshaling_policy::serialize_data(
            proof_idx, rerand_cipher_text.second,
            typename encrypted_input_policy::proof_system::primary_input_type {std::cbegin(pinput) + eid_offset,
                                                                               std::cend(pinput)},
            rerand_cipher_text.first,
            typename encrypted_input_policy::proof_system::primary_input_type {std::cbegin(pinput) + sn_offset,
                                                                               std::cbegin(pinput) + rt_offset},
            proof_blob, pinput_blob, ct_blob, sn_blob);
    logln("Marshalling finished." );
#ifdef DEBUG_VERIFY_BALLOT
    logln("Sender verifies rerandomized encrypted ballot and proof..." );
    bool enc_verification_ans = verify_encryption<encrypted_input_policy::encryption_scheme_type>(
        rerand_cipher_text.first,
        {pk_eid, gg_keypair.second, rerand_cipher_text.second,
         typename encrypted_input_policy::proof_system::primary_input_type {std::cbegin(pinput) + m.size(),
                                                                        std::cend(pinput)}});
    BOOST_ASSERT(enc_verification_ans);
    logln("Encryption verification of rerandomazed cipher text and proof finished." );
#else
    logln("Skipping ballot verification");
#endif
}

void process_encrypted_input_mode_tally_admin_phase(
        std::size_t tree_depth,
        const std::vector<std::vector<std::uint8_t>> &cts_blobs,
        const std::vector<std::uint8_t> &sk_eid_blob,
        const std::vector<std::uint8_t> &vk_eid_blob,
        const std::vector<std::uint8_t> &pk_crs_blob,
        const std::vector<std::uint8_t> &vk_crs_blob,
        std::vector<std::uint8_t> &dec_proof_blob,
        std::vector<std::uint8_t> &voting_res_blob) {

    logln("tally votes begin deserialization" );

    auto sk_eid = marshaling_policy::deserialize_sk_eid(sk_eid_blob);
    auto vk_eid = marshaling_policy::deserialize_vk_eid(vk_eid_blob);
    typename encrypted_input_policy::proof_system::keypair_type gg_keypair = {
            marshaling_policy::deserialize_pk_crs(pk_crs_blob), marshaling_policy::deserialize_vk_crs(vk_crs_blob)};
    logln("tally votes begin cts deserialization" );

    std::size_t participants_number = 1 << tree_depth;
    BOOST_ASSERT(cts_blobs.size() <= participants_number);
    std::vector<typename encrypted_input_policy::encryption_scheme_type::cipher_type::first_type> cts;
    cts.reserve(cts_blobs.size());
    for (auto proof_idx = 0; proof_idx < cts_blobs.size(); proof_idx++) {
    cts.push_back(marshaling_policy::deserialize_ct(cts_blobs[proof_idx]));
    }

    logln("tally votes finished deserialization" );

    logln("Administrator processes tally phase - aggregates encrypted ballots, decrypts aggregated ballot, "
          "generate decryption proof...", "\n");

    auto ct_agg = cts[0];
    logln("Administrator counts final results..." );
    for (auto proof_idx = 1; proof_idx < cts.size(); proof_idx++) {
        auto ct_i = cts[proof_idx];
        BOOST_ASSERT_MSG(std::size(ct_agg) == std::size(ct_i), "Wrong size of the ct!");
        for (std::size_t i = 0; i < std::size(ct_i); ++i) {
            ct_agg[i] = ct_agg[i] + ct_i[i];
        }
    }
    logln("Final results are ready." );

    logln("Final results decryption..." );
    typename encrypted_input_policy::encryption_scheme_type::decipher_type decipher_rerand_sum_text =
            decrypt<encrypted_input_policy::encryption_scheme_type,
    modes::verifiable_encryption<encrypted_input_policy::encryption_scheme_type>>(
            ct_agg, {sk_eid, vk_eid, gg_keypair});
    logln("Decryption finished." );
    BOOST_ASSERT_MSG(decipher_rerand_sum_text.first.size() == encrypted_input_policy::msg_size,
                     "Deciphered lens not equal");

    logln("Deciphered results of voting:" );
    for (std::size_t i = 0; i < encrypted_input_policy::msg_size; ++i) {
        log(decipher_rerand_sum_text.first[i].data , ", ");
    }
    logln();

    logln("Tally phase marshalling started..." );
    marshaling_policy::serialize_tally_phase_data(decipher_rerand_sum_text, dec_proof_blob, voting_res_blob);
    logln("Marshalling finished." );
}

bool process_encrypted_input_mode_tally_voter_phase(
        std::size_t tree_depth,
        const std::vector<std::vector<std::uint8_t>> &cts_blobs,
        const std::vector<std::uint8_t> &vk_eid_blob,
        const std::vector<std::uint8_t> &pk_crs_blob,
        const std::vector<std::uint8_t> &vk_crs_blob,
        const std::vector<std::uint8_t> &voting_res_blob,
        const std::vector<std::uint8_t> &dec_proof_blob) {
    
    logln("verify tally begin deserialization" );

    auto vk_eid = marshaling_policy::deserialize_vk_eid(vk_eid_blob);
    typename encrypted_input_policy::proof_system::keypair_type gg_keypair = {
            marshaling_policy::deserialize_pk_crs(pk_crs_blob), marshaling_policy::deserialize_vk_crs(vk_crs_blob)};

    auto voting_result = marshaling_policy::deserialize_scalar_vector(voting_res_blob);
    auto dec_proof = marshaling_policy::deserialize_decryption_proof(dec_proof_blob);

    logln("verify tally begin cts deserialization" );
    std::size_t participants_number = 1 << tree_depth;
    BOOST_ASSERT(cts_blobs.size() <= participants_number);
    std::vector<typename encrypted_input_policy::encryption_scheme_type::cipher_type::first_type> cts;
    cts.reserve(cts_blobs.size());
    for (auto proof_idx = 0; proof_idx < cts_blobs.size(); proof_idx++) {
    cts.push_back(marshaling_policy::deserialize_ct(cts_blobs[proof_idx]));
    }

    logln("verify tally finished deserialization" );
    
    logln("Voter processes tally phase - aggregates encrypted ballots, verifies voting result using decryption "
          "proof...", "\n");

    auto ct_agg = cts[0];
    for (auto proof_idx = 1; proof_idx < cts.size(); proof_idx++) {
        auto ct_i = cts[proof_idx];
        BOOST_ASSERT_MSG(std::size(ct_agg) == std::size(ct_i), "Wrong size of the ct!");
        for (std::size_t i = 0; i < std::size(ct_i); ++i) {
            ct_agg[i] = ct_agg[i] + ct_i[i];
        }
    }

    logln("Verification of the deciphered tally result." );
    bool dec_verification_ans = verify_decryption<encrypted_input_policy::encryption_scheme_type>(
            ct_agg, voting_result, {vk_eid, gg_keypair, dec_proof});
    BOOST_ASSERT_MSG(dec_verification_ans, "Decryption proof verification failed.");
    logln("Decryption proof verification succeeded." );
    logln("Results of voting:" );
    for (std::size_t i = 0; i < encrypted_input_policy::msg_size; ++i) {
        log(voting_result[i].data , ", ");
    }
    logln();

    return dec_verification_ans;
}