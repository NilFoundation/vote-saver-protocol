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

#include <nil/crypto3/algebra/curves/bls12.hpp>

#include <nil/crypto3/zk/snark/blueprint.hpp>
#include <nil/crypto3/zk/snark/blueprint_variable.hpp>

#include <nil/crypto3/zk/snark/schemes/ppzksnark/r1cs_gg_ppzksnark.hpp>

#include <nil/crypto3/zk/snark/algorithms/generate.hpp>

#include "ton/proof/marshalling.hpp"

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
    ("verify", "Verify proofs and/or keys")
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

    zk::snark::blueprint<field_type> bp;
    zk::snark::blueprint_variable<field_type> res, x, sum1, y, sum2;
    res.allocate(bp);
    x.allocate(bp);
    sum1.allocate(bp);
    y.allocate(bp);
    sum2.allocate(bp);

    bp.set_input_sizes(1);

    // x*x = sym_1
    bp.add_r1cs_constraint(zk::snark::r1cs_constraint<field_type>(x, x, sum1));

    // sym_1 * x = y
    bp.add_r1cs_constraint(zk::snark::r1cs_constraint<field_type>(sum1, x, y));

    // y + x = sym_2
    bp.add_r1cs_constraint(zk::snark::r1cs_constraint<field_type>(y + x, 1, sum2));

    // sym_2 + 5 = res
    bp.add_r1cs_constraint(zk::snark::r1cs_constraint<field_type>(sum2 + 5, 1, res));

    zk::snark::r1cs_constraint_system<field_type> constraint_system = bp.get_constraint_system();

    typename scheme_type::keypair_type keypair = zk::snark::generate<scheme_type>(constraint_system);

    if (vm.count("proving-key-output")) {

    }

    if (vm.count("verifying-key-output")) {

    }

    if (vm.count("proof-output")) {
        std::vector<std::uint8_t> blob;

        pack_tvm(keypair.second, primary_input, proof, blob);

        boost::filesystem::ofstream poutf(pout);
        poutf << blob;
        poutf.close();
    }

    return 0;
}