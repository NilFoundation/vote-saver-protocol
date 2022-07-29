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

#include<jni.h>
#include<string>
#include<boost/format.hpp>
#include <android/log.h>

namespace boost {
    void assertion_failed(char const *expr, char const *function, char const *file, long line) {
        std::stringstream ss;
        ss << "Error: in file " << file << ": in function " << function << ": on line " << line << std::endl;
        std::string error = ss.str();
        __android_log_write(ANDROID_LOG_ERROR, "DeVote C++",   error.c_str());
        std::terminate();
    }
    void assertion_failed_msg(char const *expr, char const *msg, char const *function, char const *file, long line) {
        std::stringstream ss;
        ss << "Error: in file " << file << ": in function " << function << ": on line " << line << std::endl
                  << std::endl;
        ss << "Error message:" << std::endl << msg << std::endl;
        std::string error = ss.str();
        __android_log_write(ANDROID_LOG_ERROR, "DeVote C++",   error.c_str());
        std::terminate();
    }
}    // namespace boost

void write_to_buffer(JNIEnv* env, const std::vector<std::uint8_t> &blob, jbyteArray buffer) {
    std::size_t blob_size = blob.size();
    std::size_t buffer_size = env->GetArrayLength(buffer);

    BOOST_ASSERT_MSG(buffer_size == blob_size, "Buffer size does not match Blob size");

    jbyte* jbyte_ptr = env->GetByteArrayElements(buffer, nullptr);
    std::copy_n(blob.begin(), blob_size, jbyte_ptr);
    env->ReleaseByteArrayElements(buffer, jbyte_ptr, 0);
}

std::vector<std::uint8_t> read_buffer(JNIEnv* env, jbyteArray buffer) {
    std::size_t buffer_size = env->GetArrayLength(buffer);
    jbyte* jbyte_ptr = env->GetByteArrayElements(buffer, nullptr);
    std::vector<std::uint8_t> blob(jbyte_ptr, jbyte_ptr + buffer_size);
    env->ReleaseByteArrayElements(buffer, jbyte_ptr, JNI_ABORT);
    return blob;
}

std::vector<std::vector<std::uint8_t>> read_buffer_array(JNIEnv* env, jobjectArray buffer_array) {
    jsize array_size = env->GetArrayLength(buffer_array);
    std::vector<std::vector<std::uint8_t>> result;
    result.reserve(array_size);
    for(jsize i = 0; i < array_size; ++i) {
        jobject obj = env->GetObjectArrayElement(buffer_array, i);
        BOOST_ASSERT(env->IsInstanceOf(obj, env->FindClass("[B")));
        auto buffer = (jbyteArray) obj;
        result.emplace_back(read_buffer(env, buffer));
    }
   return result;
}

extern "C"
JNIEXPORT void JNICALL
Java_com_devoteusa_devote_DeVoteJNI_generateVoterKeypair(JNIEnv * env,
                           jobject thiz,
                           jbyteArray pk_out,
                           jbyteArray sk_out) {
    std::vector<std::uint8_t> pk_blob;
    std::vector<std::uint8_t> sk_blob;
    process_encrypted_input_mode_init_voter_phase(0, pk_blob, sk_blob);
    write_to_buffer(env, pk_blob, pk_out);
    write_to_buffer(env, sk_blob, sk_out);
}

extern "C"
JNIEXPORT void JNICALL
Java_com_devoteusa_devote_DeVoteJNI_generateVote(JNIEnv *env, jobject thiz, jint tree_depth,
                       jint eid_bits, jint voter_idx, jint vote,
                       jbyteArray merkle_tree_buffer, jbyteArray rt_buffer,
                       jbyteArray eid_buffer, jbyteArray sk_buffer,
                       jbyteArray pk_eid_buffer,
                       jbyteArray r1cs_proving_key_buffer,
                       jbyteArray r1cs_verification_key_buffer,
                       jbyteArray proof_buffer_out,
                       jbyteArray pinput_buffer_out,
                       jbyteArray ct_buffer_out, jbyteArray sn_buffer_out) {
    std::vector<std::uint8_t> proof_blob_out;
    std::vector<std::uint8_t> pinput_blob_out;
    std::vector<std::uint8_t> ct_blob_out;
    std::vector<std::uint8_t> sn_blob_out;

    auto merkle_tree_blob = read_buffer(env, merkle_tree_buffer);
    auto rt_blob = read_buffer(env, rt_buffer);
    auto eid_blob = read_buffer(env, eid_buffer);
    auto sk_blob = read_buffer(env, sk_buffer);
    auto pk_eid_blob = read_buffer(env, pk_eid_buffer);
    auto proving_key_blob = read_buffer(env, r1cs_proving_key_buffer);
    auto verification_key_blob = read_buffer(env, r1cs_verification_key_buffer);

    process_encrypted_input_mode_vote_phase(tree_depth, eid_bits, voter_idx, vote, merkle_tree_blob,
                                            rt_blob, eid_blob, sk_blob, pk_eid_blob, proving_key_blob,
                                            verification_key_blob,
                                            proof_blob_out, pinput_blob_out, ct_blob_out, sn_blob_out);

    write_to_buffer(env, proof_blob_out, proof_buffer_out);
    write_to_buffer(env, pinput_blob_out, pinput_buffer_out);
    write_to_buffer(env, ct_blob_out, ct_buffer_out);
    write_to_buffer(env, sn_blob_out, sn_buffer_out);
}

extern "C"
JNIEXPORT jboolean Java_com_devoteusa_devote_DeVoteJNI_verifyTally(JNIEnv *env, jobject thiz,
                           jint tree_depth,
                           jobjectArray cts_buffer_array,
                           jbyteArray vk_eid_buffer,
                           jbyteArray pk_crs_buffer,
                           jbyteArray vk_crs_buffer,
                           jbyteArray dec_proof_buffer,
                           jbyteArray voting_res_buffer) {
    std::vector<std::uint8_t> vk_eid_blob = read_buffer(env, vk_eid_buffer);
    std::vector<std::uint8_t> pk_crs_blob = read_buffer(env, pk_crs_buffer);
    std::vector<std::uint8_t> vk_crs_blob = read_buffer(env, vk_crs_buffer);
    std::vector<std::uint8_t> dec_proof_blob = read_buffer(env, dec_proof_buffer);
    std::vector<std::uint8_t> voting_res_blob = read_buffer(env, voting_res_buffer);
    std::vector<std::vector<std::uint8_t>> cts_blobs = read_buffer_array(env, cts_buffer_array);

    bool is_tally_valid = process_encrypted_input_mode_tally_voter_phase(
                            tree_depth, cts_blobs, vk_eid_blob, pk_crs_blob,
                            vk_crs_blob, voting_res_blob, dec_proof_blob);

    logln((is_tally_valid ? "tally is valid": "tally is invalid"));

    return is_tally_valid;
}