//---------------------------------------------------------------------------//
// Copyright (c) 2018-2022 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2022 Ilias Khairullin <ilias@nil.foundation>
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

#include <nil/crypto3/zk/algorithms/generate.hpp>
#include <nil/crypto3/zk/algorithms/verify.hpp>
#include <nil/crypto3/zk/algorithms/prove.hpp>

#include <nil/marshalling/status_type.hpp>
#include <nil/crypto3/marshalling/zk/types/r1cs_gg_ppzksnark/primary_input.hpp>
#include <nil/crypto3/marshalling/zk/types/r1cs_gg_ppzksnark/proof.hpp>
#include <nil/crypto3/marshalling/zk/types/r1cs_gg_ppzksnark/verification_key.hpp>
#include <nil/crypto3/marshalling/zk/types/r1cs_gg_ppzksnark/proving_key.hpp>
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
        const primary_input_type &eid, const primary_input_type &rt, const std::string &r1cs_proving_key_out,
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

        serialize_initial_phase_admin_data(pk_crs, vk_crs, pk_eid,
        sk_eid, vk_eid,
        eid, rt, pk_crs_blob,
        vk_crs_blob, pk_eid_blob,
        sk_eid_blob, vk_eid_blob,
        eid_blob, rt_blob);

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

    static void serialize_initial_phase_admin_data(
        const proving_key_type &pk_crs, const verification_key_type &vk_crs, const elgamal_public_key_type &pk_eid,
        const elgamal_private_key_type &sk_eid, const elgamal_verification_key_type &vk_eid,
        const primary_input_type &eid, const primary_input_type &rt, std::vector<std::uint8_t> &r1cs_proving_key_out,
        std::vector<std::uint8_t> &r1cs_verification_key_out, std::vector<std::uint8_t> &public_key_output,
        std::vector<std::uint8_t> &secret_key_output, std::vector<std::uint8_t> &verification_key_output,
        std::vector<std::uint8_t> &eid_output, std::vector<std::uint8_t> &rt_output) {
        r1cs_proving_key_out = serialize_obj<r1cs_proving_key_marshalling_type>(
            pk_crs,
            std::function(
                nil::crypto3::marshalling::types::fill_r1cs_gg_ppzksnark_proving_key<proving_key_type, endianness>));

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

        eid_output = serialize_obj<pinput_marshaling_type>(
            eid,
            std::function(nil::crypto3::marshalling::types::fill_r1cs_gg_ppzksnark_primary_input<primary_input_type,
                                                                                                 endianness>));

        rt_output = serialize_obj<pinput_marshaling_type>(
            rt,
            std::function(nil::crypto3::marshalling::types::fill_r1cs_gg_ppzksnark_primary_input<primary_input_type,
                                                                                                 endianness>));
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

    static void serialize_data(std::size_t proof_idx, const verification_key_type &vk_crs,
                               const elgamal_public_key_type &pk_eid, const proof_type &proof,
                               const primary_input_type &pinput,
                               const encrypted_input_policy::encryption_scheme_type::cipher_type::first_type &ct,
                               const primary_input_type &eid, const primary_input_type &sn,
                               const primary_input_type &rt, std::vector<std::uint8_t> &proof_blob,
                               std::vector<std::uint8_t> &pinput_blob, std::vector<std::uint8_t> &ct_blob,
                               std::vector<std::uint8_t> &eid_blob, std::vector<std::uint8_t> &sn_blob,
                               std::vector<std::uint8_t> &rt_blob, std::vector<std::uint8_t> &vk_crs_blob,
                               std::vector<std::uint8_t> &pk_eid_blob) {
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

        eid_blob = serialize_obj<pinput_marshaling_type>(
            eid,
            std::function(nil::crypto3::marshalling::types::fill_r1cs_gg_ppzksnark_primary_input<primary_input_type,
                                                                                                 endianness>));

        sn_blob = serialize_obj<pinput_marshaling_type>(
            sn,
            std::function(nil::crypto3::marshalling::types::fill_r1cs_gg_ppzksnark_primary_input<primary_input_type,
                                                                                                 endianness>));

        rt_blob = serialize_obj<pinput_marshaling_type>(
            rt,
            std::function(nil::crypto3::marshalling::types::fill_r1cs_gg_ppzksnark_primary_input<primary_input_type,
                                                                                                 endianness>));

        vk_crs_blob = serialize_obj<r1cs_verification_key_marshaling_type>(
            vk_crs,
            std::function(
                nil::crypto3::marshalling::types::fill_r1cs_gg_ppzksnark_verification_key<verification_key_type,
                                                                                          endianness>));
        pk_eid_blob = serialize_obj<public_key_marshaling_type>(
            pk_eid,
            std::function(nil::crypto3::marshalling::types::fill_public_key<elgamal_public_key_type, endianness>));
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
    static std::array<bool, bits> deserialize_bitarray(const std::vector<std::uint8_t> &blob) {

        constexpr int octets = bits/8 + (bits%8 ? 1 : 0);
        constexpr int bits_ceil = octets*8;

        std::array<std::uint8_t, octets> in {};
        BOOST_ASSERT(blob.size() == octets);
        std::copy_n(blob.begin(), octets, in.begin());

        std::array<bool, bits_ceil> out {};
        nil::crypto3::detail::pack<nil::crypto3::stream_endian::big_octet_big_bit, nil::crypto3::stream_endian::big_octet_big_bit, 8, 1>(in.begin(), in.end(), out.begin());

        std::array<bool, bits> res;
        std::copy_n(out.begin(), bits, res.begin());

        return res;
    }


    static std::vector<std::array<bool, encrypted_input_policy::public_key_bits>> read_voters_public_keys(std::size_t tree_depth,
                                                                  const std::string &voter_public_key_output) {
        std::size_t participants_number = 1 << tree_depth;
        std::vector<std::vector<std::uint8_t>> blobs;

        for (auto i = 0; i < participants_number; i++) {
            if (!voter_public_key_output.empty()) {
                blobs.emplace_back(read_obj(voter_public_key_output + std::to_string(i) + ".bin"));
            }
        }
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
                nil::crypto3::marshalling::types::make_r1cs_gg_ppzksnark_proving_key<proving_key_type, endianness>));
    }

    static proving_key_type deserialize_pk_crs(const std::vector<std::uint8_t> &pk_crs_blob) {
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
    marshaling_policy::write_initial_phase_admin_data(
        gg_keypair.first, gg_keypair.second, std::get<0>(keypair), std::get<1>(keypair), std::get<2>(keypair),
        eid_field, rt_field, vm.count("r1cs-proving-key-output") ? vm["r1cs-proving-key-output"].as<std::string>() : "",
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

void process_encrypted_input_mode_init_admin_phase(
    std::size_t tree_depth, std::size_t eid_bits, const std::vector<std::array<bool, encrypted_input_policy::public_key_bits>> &public_keys,
    std::vector<std::uint8_t> &r1cs_proving_key_out, std::vector<std::uint8_t> &r1cs_verification_key_out,
    std::vector<std::uint8_t> &public_key_output, std::vector<std::uint8_t> &secret_key_output,
    std::vector<std::uint8_t> &verification_key_output, std::vector<std::uint8_t> &eid_output,
    std::vector<std::uint8_t> &rt_output) {
    using scalar_field_value_type = typename encrypted_input_policy::pairing_curve_type::scalar_field_type::value_type;

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

    logln("Voting system administrator generates R1CS..." );
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

    logln("Administrator initial phase marshalling started..." );
    marshaling_policy::serialize_initial_phase_admin_data(
        gg_keypair.first, gg_keypair.second, std::get<0>(keypair), std::get<1>(keypair), std::get<2>(keypair),
        eid_field, rt_field, r1cs_proving_key_out, r1cs_verification_key_out, public_key_output, secret_key_output,
        verification_key_output, eid_output, rt_output);
    logln("Marshalling finished." );
}

void process_encrypted_input_mode_vote_phase(
    std::size_t tree_depth, std::size_t eid_bits, std::size_t voter_idx, std::size_t vote, const std::vector<std::array<bool, encrypted_input_policy::public_key_bits>> &public_keys,
    const std::vector<typename marshaling_policy::scalar_field_value_type> &admin_rt_field,
    const std::vector<typename marshaling_policy::scalar_field_value_type> &eid_field, std::array<bool, encrypted_input_policy::secret_key_bits> &sk,
    const typename marshaling_policy::elgamal_public_key_type &pk_eid,
    const typename encrypted_input_policy::proof_system::keypair_type &gg_keypair,
    std::vector<std::uint8_t> &proof_blob, std::vector<std::uint8_t> &pinput_blob, std::vector<std::uint8_t> &ct_blob,
    std::vector<std::uint8_t> &eid_blob, std::vector<std::uint8_t> &sn_blob, std::vector<std::uint8_t> &rt_blob,
    std::vector<std::uint8_t> &vk_crs_blob, std::vector<std::uint8_t> &pk_eid_blob) {
    using scalar_field_value_type = typename encrypted_input_policy::pairing_curve_type::scalar_field_type::value_type;

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

    for(auto c : public_keys[proof_idx]) {
        log((int)c);
    }
    logln();

    logln("Voter with index " , proof_idx , " generates its merkle copath..." );
    auto tree = containers::make_merkle_tree<encrypted_input_policy::merkle_hash_type, encrypted_input_policy::arity>(
        std::cbegin(public_keys), std::cend(public_keys));
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
        proof_idx, gg_keypair.second, pk_eid, rerand_cipher_text.second,
        typename encrypted_input_policy::proof_system::primary_input_type {std::cbegin(pinput) + eid_offset,
                                                                           std::cend(pinput)},
        rerand_cipher_text.first,
        typename encrypted_input_policy::proof_system::primary_input_type {std::cbegin(pinput) + eid_offset,
                                                                           std::cbegin(pinput) + sn_offset},
        typename encrypted_input_policy::proof_system::primary_input_type {std::cbegin(pinput) + sn_offset,
                                                                           std::cbegin(pinput) + rt_offset},
        typename encrypted_input_policy::proof_system::primary_input_type {std::cbegin(pinput) + rt_offset,
                                                                           std::cbegin(pinput) + rt_offset_end},
        proof_blob, pinput_blob, ct_blob, eid_blob, sn_blob, rt_blob, vk_crs_blob, pk_eid_blob);
    logln("Marshalling finished." );

    logln("Sender verifies rerandomized encrypted ballot and proof..." );
    bool enc_verification_ans = verify_encryption<encrypted_input_policy::encryption_scheme_type>(
        rerand_cipher_text.first,
        {pk_eid, gg_keypair.second, rerand_cipher_text.second,
         typename encrypted_input_policy::proof_system::primary_input_type {std::cbegin(pinput) + m.size(),
                                                                            std::cend(pinput)}});
    BOOST_ASSERT(enc_verification_ans);
    logln("Encryption verification of rerandomazed cipher text and proof finished." );
}

void process_encrypted_input_mode_tally_admin_phase(
    std::size_t tree_depth,
    const std::vector<typename encrypted_input_policy::encryption_scheme_type::cipher_type::first_type> &cts,
    const typename marshaling_policy::elgamal_private_key_type &sk_eid,
    const typename marshaling_policy::elgamal_verification_key_type &vk_eid,
    const typename encrypted_input_policy::proof_system::keypair_type &gg_keypair,
    std::vector<std::uint8_t> &dec_proof_blob,
    std::vector<std::uint8_t> &voting_res_blob) {
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
    const std::vector<typename encrypted_input_policy::encryption_scheme_type::cipher_type::first_type> &cts,
    const typename marshaling_policy::elgamal_verification_key_type &vk_eid,
    const typename encrypted_input_policy::proof_system::keypair_type &gg_keypair,
    const std::vector<typename marshaling_policy::scalar_field_value_type> &voting_result,
    const typename encrypted_input_policy::encryption_scheme_type::decipher_type::second_type &dec_proof) {
    logln("Voter processes tally phase - aggregates encrypted ballots, verifies voting result using decryption "
                 "proof...", "\n");

    std::size_t participants_number = 1 << tree_depth;

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

template<typename T>
struct buffer {
    std::size_t size;
    T *ptr;
};

buffer<char> blob_to_buffer(const std::vector<std::uint8_t> &blob) {
    buffer<char> buff;
    buff.size = blob.size();
    buff.ptr = new char[buff.size];
    std::copy(blob.begin(), blob.end(), buff.ptr);
    return buff;
}

std::vector<std::uint8_t> buffer_to_blob(const buffer<char> *const buff) {
    std::vector<std::uint8_t> res(buff->ptr, buff->ptr + buff->size);
    return res;
}

std::vector<std::vector<std::uint8_t>> super_buffer_to_blobs(const buffer<buffer<char> *const> *const super_buff) {
    std::vector<std::vector<std::uint8_t>> res;
    res.reserve(super_buff->size);

    for (std::size_t i = 0; i < super_buff->size; ++i) {
        res.push_back(buffer_to_blob(super_buff->ptr[i]));
    }

    return res;
}

extern "C" {
void generate_voter_keypair(buffer<char> *const voter_pk_out, buffer<char> *const voter_sk_out) {
    std::vector<std::uint8_t> voter_pk_blob;
    std::vector<std::uint8_t> voter_sk_blob;

    // voter index only matters for prints
    process_encrypted_input_mode_init_voter_phase(0, voter_pk_blob, voter_sk_blob);

    *voter_pk_out = blob_to_buffer(voter_pk_blob);
    *voter_sk_out = blob_to_buffer(voter_sk_blob);
}

void init_election(std::size_t tree_depth, std::size_t eid_bits,
                   const buffer<buffer<char> *const> *const public_keys_super_buffer,
                   buffer<char> *const r1cs_proving_key_out, buffer<char> *const r1cs_verification_key_out,
                   buffer<char> *const public_key_out, buffer<char> *const secret_key_out,
                   buffer<char> *const verification_key_out, buffer<char> *const eid_out, buffer<char> *const rt_out) {
    std::vector<std::uint8_t> r1cs_proving_key_blob;
    std::vector<std::uint8_t> r1cs_verification_key_blob;
    std::vector<std::uint8_t> public_key_blob;
    std::vector<std::uint8_t> secret_key_blob;
    std::vector<std::uint8_t> verification_key_blob;
    std::vector<std::uint8_t> eid_blob;
    std::vector<std::uint8_t> rt_blob;

    auto blobs = super_buffer_to_blobs(public_keys_super_buffer);
    logln("Finished conversion from buffer to blobs of public keys" );

    auto public_keys = marshaling_policy::deserialize_voters_public_keys(tree_depth, blobs);

    logln("Finished deserialization of public keys" );

    process_encrypted_input_mode_init_admin_phase(tree_depth, eid_bits, public_keys, r1cs_proving_key_blob,
                                                  r1cs_verification_key_blob, public_key_blob, secret_key_blob,
                                                  verification_key_blob, eid_blob, rt_blob);

    *r1cs_proving_key_out = blob_to_buffer(r1cs_proving_key_blob);
    *r1cs_verification_key_out = blob_to_buffer(r1cs_verification_key_blob);
    *public_key_out = blob_to_buffer(public_key_blob);
    *secret_key_out = blob_to_buffer(secret_key_blob);
    *verification_key_out = blob_to_buffer(verification_key_blob);
    *eid_out = blob_to_buffer(eid_blob);
    *rt_out = blob_to_buffer(rt_blob);
}

void generate_vote(std::size_t tree_depth, std::size_t eid_bits, std::size_t voter_idx, std::size_t vote,
                   const buffer<buffer<char> *const> *const public_keys_super_buffer,
                   const buffer<char> *const rt_buffer, const buffer<char> *const eid_buffer,
                   const buffer<char> *const sk_buffer, const buffer<char> *const pk_eid_buffer,
                   const buffer<char> *const r1cs_proving_key_buffer,
                   const buffer<char> *const r1cs_verification_key_buffer, buffer<char> *const proof_buffer_out,
                   buffer<char> *const pinput_buffer_out, buffer<char> *const ct_buffer_out,
                   buffer<char> *const sn_buffer_out) {

    std::vector<std::uint8_t> proof_blob_out;
    std::vector<std::uint8_t> pinput_blob_out;
    std::vector<std::uint8_t> ct_blob_out;
    std::vector<std::uint8_t> eid_blob_out;
    std::vector<std::uint8_t> sn_blob_out;
    std::vector<std::uint8_t> rt_blob_out;
    std::vector<std::uint8_t> vk_crs_blob_out;
    std::vector<std::uint8_t> pk_eid_blob_out;

    auto blobs = super_buffer_to_blobs(public_keys_super_buffer);
    logln("Finished conversion from buffer to blobs of public keys" );

    auto public_keys = marshaling_policy::deserialize_voters_public_keys(tree_depth, blobs);
    logln("Finished deserialization of public keys" );

    auto rt_blob = buffer_to_blob(rt_buffer);
    auto eid_blob = buffer_to_blob(eid_buffer);
    auto sk_blob = buffer_to_blob(sk_buffer);
    auto pk_eid_blob = buffer_to_blob(pk_eid_buffer);
    auto proving_key_blob = buffer_to_blob(r1cs_proving_key_buffer);
    auto verification_key_blob = buffer_to_blob(r1cs_verification_key_buffer);

    logln("Finished conversion of rt,eid,sk,pk_eid,proving_key,verification_key from buffer to blob");

    auto rt_field = marshaling_policy::deserialize_scalar_vector(rt_blob);
    auto eid_field = marshaling_policy::deserialize_scalar_vector(eid_blob);
    auto sk = marshaling_policy::deserialize_bitarray<encrypted_input_policy::secret_key_bits>(sk_blob);
    auto pk_eid = marshaling_policy::deserialize_pk_eid(pk_eid_blob);

    typename encrypted_input_policy::proof_system::keypair_type gg_keypair = {
        marshaling_policy::deserialize_pk_crs(proving_key_blob),
        marshaling_policy::deserialize_vk_crs(verification_key_blob)};

    logln("Finished deserialization of rt,eid,sk,pk_eid,proving_key,verification_key");

    process_encrypted_input_mode_vote_phase(tree_depth, eid_bits, voter_idx, vote, public_keys, rt_field, eid_field, sk, pk_eid, gg_keypair,
                                            proof_blob_out, pinput_blob_out, ct_blob_out, eid_blob_out, sn_blob_out,
                                            rt_blob_out, vk_crs_blob_out, pk_eid_blob_out);

    *proof_buffer_out = blob_to_buffer(proof_blob_out);
    *pinput_buffer_out = blob_to_buffer(pinput_blob_out);
    *ct_buffer_out = blob_to_buffer(ct_blob_out);
    *sn_buffer_out = blob_to_buffer(sn_blob_out);
}

void tally_votes(std::size_t tree_depth,
                 const buffer<char> *const sk_eid_buffer,
                 const buffer<char> *const vk_eid_buffer,
                 const buffer<char> *const pk_crs_buffer,
                 const buffer<char> *const vk_crs_buffer,
                 const buffer<buffer<char> *const> *const cts_super_buffer,
                 buffer<char> *const dec_proof_buffer_out,
                 buffer<char> *const voting_res_buffer_out) {

    logln("tally votes begin deserialization" );

    std::vector<std::uint8_t> sk_eid_blob = buffer_to_blob(sk_eid_buffer);
    std::vector<std::uint8_t> vk_eid_blob = buffer_to_blob(vk_eid_buffer);
    std::vector<std::uint8_t> pk_crs_blob = buffer_to_blob(pk_crs_buffer);
    std::vector<std::uint8_t> vk_crs_blob = buffer_to_blob(vk_crs_buffer);
    std::vector<std::vector<std::uint8_t>> cts_blobs = super_buffer_to_blobs(cts_super_buffer);

    logln("tally votes finished converting from buffers to blobs" );


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

    std::vector<std::uint8_t> dec_proof_blob;
    std::vector<std::uint8_t> voting_res_blob;

    process_encrypted_input_mode_tally_admin_phase(tree_depth, cts, sk_eid, vk_eid, gg_keypair, dec_proof_blob,
                                                   voting_res_blob);
     logln("tally votes begin blobs to buffers conversion" );

    *dec_proof_buffer_out = blob_to_buffer(dec_proof_blob);
    *voting_res_buffer_out = blob_to_buffer(voting_res_blob);
     logln("tally votes finished blobs to buffers conversion" );

}

bool verify_tally(std::size_t tree_depth,
                  const buffer<buffer<char> *const> *const cts_super_buffer,
                  const buffer<char> *const vk_eid_buffer,
                  const buffer<char> *const pk_crs_buffer,
                  const buffer<char> *const vk_crs_buffer,
                  buffer<char> *const dec_proof_buffer,
                  buffer<char> *const voting_res_buffer
) {
    logln("verify tally begin deserialization" );

    std::vector<std::uint8_t> vk_eid_blob = buffer_to_blob(vk_eid_buffer);
    std::vector<std::uint8_t> pk_crs_blob = buffer_to_blob(pk_crs_buffer);
    std::vector<std::uint8_t> vk_crs_blob = buffer_to_blob(vk_crs_buffer);
    std::vector<std::uint8_t> dec_proof_blob = buffer_to_blob(dec_proof_buffer);
    std::vector<std::uint8_t> voting_res_blob = buffer_to_blob(voting_res_buffer);
    std::vector<std::vector<std::uint8_t>> cts_blobs = super_buffer_to_blobs(cts_super_buffer);

    logln("verify tally finished converting from buffers to blobs" );

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

    bool is_tally_valid = process_encrypted_input_mode_tally_voter_phase(tree_depth, cts, vk_eid, gg_keypair, voting_result,
                                                           dec_proof);

    logln((is_tally_valid ? "tally is valid": "tally is invalid"));

    return is_tally_valid;
}

}

void test() {
    std::vector<std::vector<std::uint8_t>> pks(4);
    std::vector<std::vector<std::uint8_t>> sks(4);
    
    for(int i = 0; i < 4; ++i) {
        process_encrypted_input_mode_init_voter_phase(i, pks[i], sks[i]);
    }

    std::size_t tree_depth = 2;
    std::size_t eid_bits = 64;
    const std::vector<std::array<bool, encrypted_input_policy::public_key_bits>> public_keys = marshaling_policy::deserialize_voters_public_keys(tree_depth, pks);

    std::vector<std::uint8_t> r1cs_proving_key_out;
    std::vector<std::uint8_t> r1cs_verification_key_out;

    std::vector<std::uint8_t> public_key_output;
    std::vector<std::uint8_t> secret_key_output;
    std::vector<std::uint8_t> verification_key_output;
    std::vector<std::uint8_t> eid_output;
    std::vector<std::uint8_t> rt_output;

    process_encrypted_input_mode_init_admin_phase(
    tree_depth, eid_bits, public_keys,
    r1cs_proving_key_out, r1cs_verification_key_out,
    public_key_output, secret_key_output,
    verification_key_output, eid_output,
    rt_output);

    std::size_t voter_idx = 0;
    std::size_t vote = 1;
    auto rt_field = marshaling_policy::deserialize_scalar_vector(rt_output);
    auto eid_field = marshaling_policy::deserialize_scalar_vector(eid_output);
    auto sk = marshaling_policy::deserialize_bitarray<encrypted_input_policy::secret_key_bits>(sks[voter_idx]);
    auto pk_eid = marshaling_policy::deserialize_pk_eid(public_key_output);

    typename encrypted_input_policy::proof_system::keypair_type gg_keypair = {
        marshaling_policy::deserialize_pk_crs(r1cs_proving_key_out),
        marshaling_policy::deserialize_vk_crs(r1cs_verification_key_out)};
    std::vector<std::uint8_t> proof_blob;
    std::vector<std::uint8_t> pinput_blob;
    std::vector<std::uint8_t> ct_blob;
    std::vector<std::uint8_t> eid_blob;
    std::vector<std::uint8_t> sn_blob;
    std::vector<std::uint8_t> rt_blob;
    std::vector<std::uint8_t> vk_crs_blob;
    std::vector<std::uint8_t> pk_eid_blob;
    process_encrypted_input_mode_vote_phase(
    tree_depth, eid_bits, voter_idx, vote, public_keys,
    rt_field,
    eid_field, sk,
    pk_eid,
    gg_keypair,
    proof_blob, pinput_blob, ct_blob,
    eid_blob, sn_blob, rt_blob,
    vk_crs_blob, pk_eid_blob);
}

int main(int argc, char *argv[]) {
#if __EMSCRIPTEN__

#else
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

            auto public_keys = marshaling_policy::read_voters_public_keys(
                tree_depth, vm.count("voter-public-key-output") ? vm["voter-public-key-output"].as<std::string>() : "");

            process_encrypted_input_mode_init_admin_phase(tree_depth, vm["eid-bits"].as<std::size_t>(), public_keys,
                                                          r1cs_proving_key_out, r1cs_verification_key_out,
                                                          public_key_output, secret_key_output, verification_key_output,
                                                          eid_output, rt_output);
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

            process_encrypted_input_mode_vote_phase(tree_depth, eid_bits, proof_idx, vote, public_keys, admin_rt_field, eid_field, sk,
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
#endif

    return 0;
}