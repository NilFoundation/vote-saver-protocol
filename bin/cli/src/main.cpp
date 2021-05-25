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

#include <boost/filesystem.hpp>
#include <boost/program_options.hpp>

#include "detail/r1cs_examples.hpp"
#include "detail/sha256_component.hpp"

#include <nil/crypto3/algebra/curves/bls12.hpp>
#include <nil/crypto3/algebra/fields/bls12/base_field.hpp>
#include <nil/crypto3/algebra/fields/bls12/scalar_field.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/bls12.hpp>
#include <nil/crypto3/algebra/curves/params/multiexp/bls12.hpp>
#include <nil/crypto3/algebra/curves/params/wnaf/bls12.hpp>
#include <nil/crypto3/algebra/curves/detail/marshalling.hpp>

#include <nil/crypto3/zk/snark/blueprint.hpp>
#include <nil/crypto3/zk/snark/blueprint_variable.hpp>

#include <nil/crypto3/zk/snark/schemes/ppzksnark/r1cs_gg_ppzksnark.hpp>
#include <nil/crypto3/zk/snark/schemes/ppzksnark/r1cs_gg_ppzksnark/marshalling.hpp>

#include <nil/crypto3/zk/snark/algorithms/generate.hpp>

#include <ton/proof/marshalling/tvm.hpp>



using namespace nil::crypto3;

typedef algebra::curves::bls12<381> curve_type;
typedef typename curve_type::scalar_field_type field_type;

typedef zk::snark::r1cs_gg_ppzksnark<curve_type> scheme_type;

int f(int argc, char *argv[]) {
    boost::filesystem::path pout, pkout, vkout;
    boost::program_options::options_description options(
        "R1CS Generic Group PreProcessing Zero-Knowledge Succinct Non-interactive ARgument of Knowledge "
        "(https://eprint.iacr.org/2016/260.pdf) CLI Proof Generator");
    // clang-format off
    options.add_options()("help,h", "Display help message")
    ("version,v", "Display version")
    ("generate", "Generate proofs and/or keys")
    ("verify", "verify proofs and/or keys")
    ("proof-output,po", boost::program_options::value<boost::filesystem::path>(&pout)->default_value("proof"))
    ("proving-key-output,pko", boost::program_options::value<boost::filesystem::path>(&pkout)->default_value("pkey"))
    ("verifying-key-output,vko", boost::program_options::value<boost::filesystem::path>(&vkout)->default_value("vkey"));
    // clang-format on

    boost::program_options::variables_map vm;
    boost::program_options::store(boost::program_options::command_line_parser(argc, argv).options(options).run(), vm);
    boost::program_options::notify(vm);

    if (vm.count("help") || argc < 2) {
        std::cout << options << std::endl;
        return 0;
    }

    std::cout << "SHA2-256 blueprint generation started." << std::endl;

    blueprint<field_type> bp = sha2_two_to_one_bp<field_type>();

    std::cout << "SHA2-256 blueprint generation finished." << std::endl;

    std::cout << "R1CS generation started." << std::endl;

    r1cs_example<field_type> example =
        r1cs_example<field_type>(bp.get_constraint_system(), bp.primary_input(), bp.auxiliary_input());

    std::cout << "R1CS generation finished." << std::endl;

    //const bool bit = run_r1cs_gg_ppzksnark<curve_type>(example);

    // zk::snark::detail::r1cs_example<field_type> example =
    //     zk::snark::detail::r1cs_example<field_type>(bp.get_constraint_system(), bp.primary_input(), bp.auxiliary_input());

    //zk::snark::r1cs_constraint_system<field_type> constraint_system = bp.get_constraint_system();

    std::cout << "Starting generator" << std::endl;

    typename scheme_type::keypair_type keypair = zk::snark::generate<scheme_type>(example.constraint_system);

    std::cout << "Starting prover" << std::endl;

    const typename scheme_type::proof_type proof = prove<scheme_type>(keypair.first, example.primary_input, example.auxiliary_input);

    // std::cout << "Starting verifier" << std::endl;

    // const bool ans = verify<basic_proof_system>(keypair.second, example.primary_input, proof);

    // std::cout << "Verifier finished, result: " << ans << std::endl;

    if (vm.count("proving-key-output")) {
    }

    if (vm.count("verifying-key-output")) {
    }

    if (vm.count("proof-output")) {
        std::vector<std::uint8_t> blob;

        pack_tvm<curve_type>(keypair.second, example.primary_input, proof, blob.begin());

        boost::filesystem::ofstream poutf(pout);
        for (const auto &v : blob) {
            poutf << v;
        }
        poutf.close();
    }

    return 0;
}

int main(){

    using namespace nil::crypto3::zk::snark;
    
    r1cs_example<typename curve_type::scalar_field_type> example =
        generate_r1cs_example_with_binary_input<typename curve_type::scalar_field_type>(50, 5);
    
    std::cout << "Starting generator" << std::endl;

    typename scheme_type::keypair_type keypair =
        generate<scheme_type>(example.constraint_system);

    std::cout << "Starting prover" << std::endl;

    typename scheme_type::proof_type proof =
        prove<scheme_type>(keypair.first, example.primary_input, example.auxiliary_input);

    std::cout << std::hex << "Obtained proof: " << proof.g_A.to_affine().X.data << " " << proof.g_A.to_affine().Y.data << " " << proof.g_A.to_affine().Z.data << std::endl
                                                << proof.g_B.to_affine().X.data[0].data << " " << proof.g_B.to_affine().X.data[1].data << " " << proof.g_B.to_affine().Y.data[0].data << std::endl
                                                << proof.g_B.to_affine().Y.data[1].data << " " << proof.g_B.to_affine().Z.data[0].data << " " << proof.g_B.to_affine().Z.data[1].data << std::endl
                                                << proof.g_C.to_affine().X.data << " " << proof.g_C.to_affine().Y.data << " " << proof.g_C.to_affine().Z.data << std::endl;

    std::cout << std::hex << "Obtained verification key: " << "gamma_g2: " 
                                                << keypair.second.gamma_g2.to_affine().X.data[0].data << " " << keypair.second.gamma_g2.to_affine().Y.data[0].data << " " << keypair.second.gamma_g2.to_affine().Z.data[0].data << std::endl
                                                << keypair.second.gamma_g2.to_affine().X.data[1].data << " " << keypair.second.gamma_g2.to_affine().Y.data[1].data << " " << keypair.second.gamma_g2.to_affine().Z.data[1].data << std::endl
                                                << "delta_g2: " 
                                                << keypair.second.delta_g2.to_affine().X.data[0].data << " " << keypair.second.delta_g2.to_affine().Y.data[0].data << " " << keypair.second.delta_g2.to_affine().Z.data[0].data << std::endl
                                                << keypair.second.delta_g2.to_affine().X.data[1].data << " " << keypair.second.delta_g2.to_affine().Y.data[1].data << " " << keypair.second.delta_g2.to_affine().Z.data[1].data << std::endl;

    std::cout << std::hex << "Obtained primary input: " << std::endl;

    for (auto it = example.primary_input.begin(); it != example.primary_input.end(); it++){
        std::cout << std::hex << it->data << " " ;
    }
    std::cout << std::endl;


    std::vector<std::uint8_t> verification_key_byteblob = nil::marshalling::verifier_input_serializer_tvm<scheme_type>::process(
        keypair.second);
    std::vector<std::uint8_t> primary_input_byteblob = nil::marshalling::verifier_input_serializer_tvm<scheme_type>::process(
        example.primary_input);
    std::vector<std::uint8_t> proof_byteblob = nil::marshalling::verifier_input_serializer_tvm<scheme_type>::process(
        proof);

    std::cout << "Verification key byteblob, size " << std::dec << verification_key_byteblob.size() << std::endl;

    for (auto it = verification_key_byteblob.begin(); it != verification_key_byteblob.end(); ++it){
        std::cout << std::hex << std::size_t(*it) << " " ;
    }

    std::cout << std::endl;

    std::cout << "Primary input byteblob, size " << std::dec << primary_input_byteblob.size() << std::endl;

    for (auto it = primary_input_byteblob.begin(); it != primary_input_byteblob.end(); ++it){
        std::cout << std::hex << std::size_t(*it) << " " ;
    }

    std::cout << std::endl;

    std::cout << "Proof byteblob, size " << std::dec << proof_byteblob.size() << std::endl;

    for (auto it = proof_byteblob.begin(); it != proof_byteblob.end(); ++it){
        std::cout << std::hex << std::size_t(*it) << " " ;
    }

    std::cout << std::endl;

    std::vector<std::uint8_t> byteblob;

    byteblob.insert (byteblob.end(), proof_byteblob.begin(), proof_byteblob.end());
    byteblob.insert (byteblob.end(), primary_input_byteblob.begin(), primary_input_byteblob.end());
    byteblob.insert (byteblob.end(), verification_key_byteblob.begin(), verification_key_byteblob.end());

    std::cout << "Data converted to byte blob" << std::endl;

    boost::filesystem::path pout("data.bin");
    boost::filesystem::ofstream poutf(pout);

    for (auto it = byteblob.begin(); it != byteblob.end(); ++it){
        std::cout << std::hex << std::size_t(*it) << " " ;
        poutf << *it;
    }

    std::cout << std::endl;

    poutf.close();

    std::cout << "Starting verifier with plain input" << std::endl;

    bool ans = verify<scheme_type>(keypair.second, example.primary_input, proof);

    std::cout << "Verifier with plain input finished, result: " << ans << std::endl;

    typename scheme_type::proof_type de_prf = nil::marshalling::verifier_input_deserializer_tvm<scheme_type>::proof_process(proof_byteblob.cbegin(), proof_byteblob.cend());
    typename scheme_type::primary_input_type de_pi = nil::marshalling::verifier_input_deserializer_tvm<scheme_type>::primary_input_process(primary_input_byteblob.cbegin(), primary_input_byteblob.cend());
    typename scheme_type::verification_key_type de_vk = nil::marshalling::verifier_input_deserializer_tvm<scheme_type>::verification_key_process(verification_key_byteblob.cbegin(), verification_key_byteblob.cend());

    std::cout << std::hex << "Decoded proof: " << de_prf.g_A.to_affine().X.data << " " << de_prf.g_A.to_affine().Y.data << " " << de_prf.g_A.to_affine().Z.data << std::endl
                                                << de_prf.g_B.to_affine().X.data[0].data << " " << de_prf.g_B.to_affine().X.data[1].data << " " << de_prf.g_B.to_affine().Y.data[0].data << std::endl
                                                << de_prf.g_B.to_affine().Y.data[1].data << " " << de_prf.g_B.to_affine().Z.data[0].data << " " << de_prf.g_B.to_affine().Z.data[1].data << std::endl
                                                << de_prf.g_C.to_affine().X.data << " " << de_prf.g_C.to_affine().Y.data << " " << de_prf.g_C.to_affine().Z.data << std::endl;

    assert (de_prf == proof);

    std::cout << std::hex << "Decoded primary input: " << std::endl;

    for (auto it = de_pi.begin(); it != de_pi.end(); it++){
        std::cout << std::hex << it->data << " " ;
    }
    std::cout << std::endl;

    // assert (de_pi == example.primary_input);

    std::cout << std::hex << "Decoded verification key: " << "gamma_g2: " 
                                                << de_vk.gamma_g2.to_affine().X.data[0].data << " " << de_vk.gamma_g2.to_affine().Y.data[0].data << " " << de_vk.gamma_g2.to_affine().Z.data[0].data << std::endl
                                                << de_vk.gamma_g2.to_affine().X.data[1].data << " " << de_vk.gamma_g2.to_affine().Y.data[1].data << " " << de_vk.gamma_g2.to_affine().Z.data[1].data << std::endl
                                                << "delta_g2: " 
                                                << de_vk.delta_g2.to_affine().X.data[0].data << " " << de_vk.delta_g2.to_affine().Y.data[0].data << " " << de_vk.delta_g2.to_affine().Z.data[0].data << std::endl
                                                << de_vk.delta_g2.to_affine().X.data[1].data << " " << de_vk.delta_g2.to_affine().Y.data[1].data << " " << de_vk.delta_g2.to_affine().Z.data[1].data << std::endl;

    assert (de_vk == keypair.second);

    std::cout << "Starting verifier with decoded input" << std::endl;

    ans = verify<scheme_type>(de_vk, de_pi, de_prf);

    std::cout << "Verifier with decoded input finished, result: " << ans << std::endl;

    return 0;
}