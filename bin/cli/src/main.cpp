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

#include <nil/crypto3/algebra/curves/bls12.hpp>
#include <nil/crypto3/algebra/fields/bls12/base_field.hpp>
#include <nil/crypto3/algebra/fields/bls12/scalar_field.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/bls12.hpp>
#include <nil/crypto3/algebra/curves/params/multiexp/bls12.hpp>
#include <nil/crypto3/algebra/curves/params/wnaf/bls12.hpp>

#include <nil/crypto3/zk/snark/blueprint.hpp>
#include <nil/crypto3/zk/snark/blueprint_variable.hpp>

#include <nil/crypto3/zk/snark/schemes/ppzksnark/r1cs_gg_ppzksnark.hpp>

#include <nil/crypto3/zk/snark/algorithms/generate.hpp>

#include <ton/proof/marshalling/tvm.hpp>



using namespace nil::crypto3;

typedef algebra::curves::bls12<381> curve_type;
typedef typename curve_type::scalar_field_type field_type;

typedef zk::snark::r1cs_gg_ppzksnark<curve_type> scheme_type;

int main(int argc, char *argv[]) {
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
    
    blueprint<FieldType> bp;
    blueprint_variable_vector<FieldType> A;
    A.allocate(bp, n);
    blueprint_variable_vector<FieldType> B;
    B.allocate(bp, n);

    blueprint_variable<FieldType> result;
    result.allocate(bp);

    components::inner_product_component<FieldType> g(bp, A, B, result);
    g.generate_r1cs_constraints();

    for (std::size_t i = 0; i < 1ul << n; ++i) {
        for (std::size_t j = 0; j < 1ul << n; ++j) {
            std::size_t correct = 0;
            for (std::size_t k = 0; k < n; ++k) {
                bp.val(A[k]) = (i & (1ul << k) ? FieldType::value_type::one() : FieldType::value_type::zero());
                bp.val(B[k]) = (j & (1ul << k) ? FieldType::value_type::one() : FieldType::value_type::zero());
                correct += ((i & (1ul << k)) && (j & (1ul << k)) ? 1 : 0);
            }

            g.generate_r1cs_witness();

            BOOST_CHECK(bp.val(result) == typename FieldType::value_type(correct));
            BOOST_CHECK(bp.is_satisfied());

            bp.val(result) = typename FieldType::value_type(100 * n + 19);
            BOOST_CHECK(!bp.is_satisfied());
        }
    }

    zk::snark::detail::r1cs_example<field_type> example =
        zk::snark::detail::r1cs_example<field_type>(bp.get_constraint_system(), bp.primary_input(), bp.auxiliary_input());

    //zk::snark::r1cs_constraint_system<field_type> constraint_system = bp.get_constraint_system();

    typename scheme_type::keypair_type keypair = zk::snark::generate<scheme_type>(example.constraint_system);

    const typename scheme_type::proof_type proof = prove<scheme_type>(keypair.first, example.primary_input, example.auxiliary_input);

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
