//---------------------------------------------------------------------------//
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

void admin_keygen(std::size_t tree_depth, std::size_t eid_bits,
                    buffer<char> *const r1cs_proving_key_out, buffer<char> *const r1cs_verification_key_out,
                    buffer<char> *const public_key_out, buffer<char> *const secret_key_out,
                    buffer<char> *const verification_key_out) {
    std::vector<std::uint8_t> r1cs_proving_key_blob;
    std::vector<std::uint8_t> r1cs_verification_key_blob;
    std::vector<std::uint8_t> public_key_blob;
    std::vector<std::uint8_t> secret_key_blob;
    std::vector<std::uint8_t> verification_key_blob;

    process_encrypted_input_mode_init_admin_phase_generate_keys(
            tree_depth, eid_bits,
            r1cs_proving_key_blob, r1cs_verification_key_blob,
            public_key_blob, secret_key_blob,
            verification_key_blob);

    *r1cs_proving_key_out = blob_to_buffer(r1cs_proving_key_blob);
    *r1cs_verification_key_out = blob_to_buffer(r1cs_verification_key_blob);
    *public_key_out = blob_to_buffer(public_key_blob);
    *secret_key_out = blob_to_buffer(secret_key_blob);
    *verification_key_out = blob_to_buffer(verification_key_blob);
}

void init_election(std::size_t tree_depth, std::size_t eid_bits,
                    const buffer<buffer<char> *const> *const public_keys_super_buffer,
                    buffer<char> *const eid_out, buffer<char> *const rt_out,
                    buffer<char> *const merkle_tree_out) {
    std::vector<std::uint8_t> eid_blob;
    std::vector<std::uint8_t> rt_blob;
    std::vector<std::uint8_t> merkle_tree_blob;

    auto public_keys_blobs = super_buffer_to_blobs(public_keys_super_buffer);
    logln("Finished conversion from buffer to blobs of public keys" );

    process_encrypted_input_mode_init_admin_phase_generate_data(
            tree_depth, eid_bits, public_keys_blobs,
            eid_blob,
            rt_blob, merkle_tree_blob);

    *eid_out = blob_to_buffer(eid_blob);
    *rt_out = blob_to_buffer(rt_blob);
    *merkle_tree_out = blob_to_buffer(merkle_tree_blob);
}

void generate_vote(std::size_t tree_depth, std::size_t eid_bits, std::size_t voter_idx, std::size_t vote,
                   const buffer<char> *const merkle_tree_buffer,
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

    auto merkle_tree_blob = buffer_to_blob(merkle_tree_buffer);
    auto rt_blob = buffer_to_blob(rt_buffer);
    auto eid_blob = buffer_to_blob(eid_buffer);
    auto sk_blob = buffer_to_blob(sk_buffer);
    auto pk_eid_blob = buffer_to_blob(pk_eid_buffer);
    auto proving_key_blob = buffer_to_blob(r1cs_proving_key_buffer);
    auto verification_key_blob = buffer_to_blob(r1cs_verification_key_buffer);

    logln("Finished conversion of merkle_tree,rt,eid,sk,pk_eid,proving_key,verification_key from buffer to blob");

    process_encrypted_input_mode_vote_phase(tree_depth, eid_bits, voter_idx, vote, merkle_tree_blob, rt_blob, eid_blob, sk_blob, pk_eid_blob, proving_key_blob, verification_key_blob,
                                            proof_blob_out, pinput_blob_out, ct_blob_out, sn_blob_out);

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

std::vector<std::uint8_t> sk_eid_blob = buffer_to_blob(sk_eid_buffer);
std::vector<std::uint8_t> vk_eid_blob = buffer_to_blob(vk_eid_buffer);
std::vector<std::uint8_t> pk_crs_blob = buffer_to_blob(pk_crs_buffer);
std::vector<std::uint8_t> vk_crs_blob = buffer_to_blob(vk_crs_buffer);
std::vector<std::vector<std::uint8_t>> cts_blobs = super_buffer_to_blobs(cts_super_buffer);

logln("tally votes finished converting from buffers to blobs" );

std::vector<std::uint8_t> dec_proof_blob;
std::vector<std::uint8_t> voting_res_blob;

process_encrypted_input_mode_tally_admin_phase(tree_depth, cts_blobs, sk_eid_blob,
                                               vk_eid_blob, pk_crs_blob, vk_crs_blob, dec_proof_blob,
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
std::vector<std::uint8_t> vk_eid_blob = buffer_to_blob(vk_eid_buffer);
std::vector<std::uint8_t> pk_crs_blob = buffer_to_blob(pk_crs_buffer);
std::vector<std::uint8_t> vk_crs_blob = buffer_to_blob(vk_crs_buffer);
std::vector<std::uint8_t> dec_proof_blob = buffer_to_blob(dec_proof_buffer);
std::vector<std::uint8_t> voting_res_blob = buffer_to_blob(voting_res_buffer);
std::vector<std::vector<std::uint8_t>> cts_blobs = super_buffer_to_blobs(cts_super_buffer);

logln("verify tally finished converting from buffers to blobs" );

bool is_tally_valid = process_encrypted_input_mode_tally_voter_phase(tree_depth, cts_blobs, vk_eid_blob, pk_crs_blob, vk_crs_blob, voting_res_blob,
                                                                     dec_proof_blob);

logln((is_tally_valid ? "tally is valid": "tally is invalid"));

return is_tally_valid;
}

}