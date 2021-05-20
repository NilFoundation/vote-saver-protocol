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
// @file Declaration of interfaces for a R1CS example, as well as functions to sample
// R1CS examples with prescribed parameters (according to some distribution).
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BLUEPRINT_TVM_R1CS_EXAMPLES_TEST_HPP
#define CRYPTO3_BLUEPRINT_TVM_R1CS_EXAMPLES_TEST_HPP

#include <nil/crypto3/zk/snark/relations/constraint_satisfaction_problems/r1cs.hpp>

#include <nil/crypto3/algebra/random_element.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                using namespace nil::crypto3::algebra;

                /**
                 * A R1CS example comprises a R1CS constraint system, R1CS input, and R1CS witness.
                 */
                template<typename FieldType>
                struct r1cs_example {
                    r1cs_constraint_system<FieldType> constraint_system;
                    r1cs_primary_input<FieldType> primary_input;
                    r1cs_auxiliary_input<FieldType> auxiliary_input;

                    r1cs_example<FieldType>() = default;
                    r1cs_example<FieldType>(const r1cs_example<FieldType> &other) = default;
                    r1cs_example<FieldType>(const r1cs_constraint_system<FieldType> &constraint_system,
                                            const r1cs_primary_input<FieldType> &primary_input,
                                            const r1cs_auxiliary_input<FieldType> &auxiliary_input) :
                        constraint_system(constraint_system),
                        primary_input(primary_input), auxiliary_input(auxiliary_input) {};
                    r1cs_example<FieldType>(r1cs_constraint_system<FieldType> &&constraint_system,
                                            r1cs_primary_input<FieldType> &&primary_input,
                                            r1cs_auxiliary_input<FieldType> &&auxiliary_input) :
                        constraint_system(std::move(constraint_system)),
                        primary_input(std::move(primary_input)), auxiliary_input(std::move(auxiliary_input)) {};
                };

            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_TVM_R1CS_EXAMPLES_TEST_HPP
