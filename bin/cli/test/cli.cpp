//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// MIT License
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE vote_saver_cli_test

#include <iostream>
#include <unordered_map>

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

#include "../include/nil/vote_saver/common.hpp"

BOOST_AUTO_TEST_SUITE(vote_saver_cli_test_suite)

BOOST_AUTO_TEST_CASE(vote_saver_first) {

    std::size_t tree_depth = 5;
    std::size_t eid_bits = 64;

    std::size_t num_participants = 1 << tree_depth;
    std::vector<std::vector<std::uint8_t>> pks(num_participants);
    std::vector<std::vector<std::uint8_t>> sks(num_participants);

    for (int i = 0; i < num_participants; ++i) {
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

    process_encrypted_input_mode_init_admin_phase_generate_keys(tree_depth, eid_bits, r1cs_proving_key_out,
                                                                r1cs_verification_key_out, public_key_output,
                                                                secret_key_output, verification_key_output);

    process_encrypted_input_mode_init_admin_phase_generate_data(tree_depth, eid_bits, pks, eid_output, rt_output,
                                                                merkle_tree_output);

    auto start = std::chrono::high_resolution_clock::now();

    std::size_t voter_idx = 0;
    std::size_t vote = 1;

    std::vector<std::uint8_t> proof_blob;
    std::vector<std::uint8_t> pinput_blob;
    std::vector<std::uint8_t> ct_blob;
    std::vector<std::uint8_t> sn_blob;

    process_encrypted_input_mode_vote_phase(tree_depth, eid_bits, voter_idx, vote, merkle_tree_output, rt_output,
                                            eid_output, secret_key_output, public_key_output, r1cs_proving_key_out,
                                            verification_key_output, proof_blob, pinput_blob, ct_blob, sn_blob);
    auto duration =
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - start);
    std::cout << "Vote Phase Time_execution: " << duration.count() << "ms" << std::endl;
}

BOOST_AUTO_TEST_SUITE_END()