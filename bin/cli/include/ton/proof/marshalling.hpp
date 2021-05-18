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

#ifndef CRYPTO3_R1CS_GG_PPZKSNARK_TYPES_TVM_MARSHALLING_HPP
#define CRYPTO3_R1CS_GG_PPZKSNARK_TYPES_TVM_MARSHALLING_HPP

#include <cstdlib>
#include <iostream>

#include <nil/crypto3/zk/snark/blueprint.hpp>

#include <nil/crypto3/zk/snark/algorithms/generate.hpp>
#include <nil/crypto3/zk/snark/algorithms/verify.hpp>
#include <nil/crypto3/zk/snark/algorithms/prove.hpp>

#include <vector>

#include <nil/crypto3/multiprecision/number.hpp>
#include <nil/crypto3/multiprecision/cpp_int.hpp>
#include <nil/crypto3/multiprecision/modular/modular_adaptor.hpp>

#include <nil/crypto3/zk/snark/schemes/ppzksnark/r1cs_gg_ppzksnark.hpp>
#include <nil/crypto3/zk/snark/sparse_vector.hpp>
#include <nil/crypto3/zk/snark/accumulation_vector.hpp>

#include <nil/crypto3/detail/pack.hpp>
#include <nil/crypto3/detail/stream_endian.hpp>

#include <nil/crypto3/zk/snark/schemes/ppzksnark/r1cs_gg_ppzksnark.hpp>

#include <nil/crypto3/algebra/curves/bls12.hpp>

using namespace nil::crypto3::zk::snark;
using namespace nil::crypto3::algebra;

template<typename ProofSystem>
class verifier_data_to_bits;

// TODO: reimplement private functions using field value type trait
template<typename CurveType>
class verifier_data_to_bits<r1cs_gg_ppzksnark<CurveType>> {
    using scheme_type = r1cs_gg_ppzksnark<CurveType>;

    constexpr static const std::size_t modulus_bits = CurveType::base_field_type::modulus_bits;

    typedef nil::crypto3::multiprecision::number<nil::crypto3::multiprecision::backends::cpp_int_backend<>>
        modulus_type;

    using chunk_type = std::uint8_t;

    constexpr static const std::size_t chunk_size = 8;
    constexpr static const std::size_t modulus_chunks = modulus_bits / chunk_size + modulus_bits % chunk_size;

    template<typename FieldType>

    static inline typename std::enable_if<!::nil::crypto3::detail::is_extended_field<FieldType>::value, void>::type
        field_type_process(typename FieldType::value_type input_fp,
                           typename std::vector<chunk_type>::iterator &write_iter) {

        nil::crypto3::multiprecision::export_bits(modulus_type(input_fp.data), write_iter, chunk_size, false);
        write_iter += modulus_chunks;
    }

    template<typename FieldType>
    static inline typename std::enable_if<::nil::crypto3::detail::is_extended_field<FieldType>::value, void>::type
        field_type_process(typename FieldType::value_type input_fp,
                           typename std::vector<chunk_type>::iterator &write_iter) {

        using field_type = FieldType;

        const std::size_t data_dimension = field_type::arity / field_type::underlying_field_type::arity;

        for (int n = 0; n < data_dimension; ++n) {
            field_type_process<typename field_type::underlying_field_type>(input_fp.data[n], write_iter);
        }
    }

    template<typename GroupType>
    static inline void group_type_process(typename GroupType::value_type input_g,
                                          typename std::vector<chunk_type>::iterator &write_iter) {

        field_type_process<typename GroupType::underlying_field_type>(input_g.X, write_iter);
        field_type_process<typename GroupType::underlying_field_type>(input_g.Y, write_iter);
        field_type_process<typename GroupType::underlying_field_type>(input_g.Z, write_iter);
    }

    static inline void std_size_t_process(std::size_t input_s, std::vector<chunk_type>::iterator &write_iter) {

        std::vector<std::size_t> vector_s = {input_s};

        auto internal_write_iter = write_iter;
        nil::crypto3::detail::pack_to<nil::crypto3::stream_endian::big_octet_big_bit, 32, 8>(vector_s,
                                                                                             internal_write_iter);

        write_iter += sizeof(std::size_t);
    }

    template<typename T>
    static inline void sparse_vector_process(sparse_vector<T> input_sp,
                                             typename std::vector<chunk_type>::iterator &write_iter) {

        std::size_t indices_count = input_sp.size();

        std_size_t_process(indices_count, write_iter);

        for (std::size_t i = 0; i < indices_count; i++) {
            std_size_t_process(input_sp.indices[i], write_iter);
        }

        std::size_t values_count = input_sp.values.size();

        std_size_t_process(values_count, write_iter);

        for (std::size_t i = 0; i < values_count; i++) {
            group_type_process<T>(input_sp.values[i], write_iter);
        }

        std_size_t_process(input_sp.domain_size_, write_iter);
    }

    template<typename T>
    static inline void accumulation_vector_process(accumulation_vector<T> input_acc,
                                                   typename std::vector<chunk_type>::iterator &write_iter) {

        group_type_process<T>(input_acc.first, write_iter);
        sparse_vector_process(input_acc.rest, write_iter);
    }

    static inline void verification_key_process(typename scheme_type::verification_key_type vk,
                                                typename std::vector<chunk_type>::iterator &write_iter) {

        field_type_process<typename CurveType::gt_type>(vk.alpha_g1_beta_g2, write_iter);
        group_type_process<typename CurveType::g2_type>(vk.gamma_g2, write_iter);
        group_type_process<typename CurveType::g2_type>(vk.delta_g2, write_iter);

        accumulation_vector_process(vk.gamma_ABC_g1, write_iter);
    }

    static inline void primary_input_process(typename scheme_type::primary_input_type pi,
                                             typename std::vector<chunk_type>::iterator &write_iter) {

        std::size_t pi_count = pi.size();

        std_size_t_process(pi_count, write_iter);

        for (std::size_t i = 0; i < pi_count; i++) {
            field_type_process<typename CurveType::scalar_field_type>(pi[i], write_iter);
        }
    }

    static inline void proof_process(typename scheme_type::proof_type pr,
                                     typename std::vector<chunk_type>::iterator &write_iter) {

        group_type_process<typename CurveType::g1_type>(pr.g_A, write_iter);
        group_type_process<typename CurveType::g2_type>(pr.g_B, write_iter);
        group_type_process<typename CurveType::g1_type>(pr.g_C, write_iter);
    }

public:
    struct verifier_data {
        typename scheme_type::verification_key_type vk;
        typename scheme_type::primary_input_type pi;
        typename scheme_type::proof_type pr;

        verifier_data() {};

        verifier_data(typename scheme_type::verification_key_type vk,
                      typename scheme_type::primary_input_type pi,
                      typename scheme_type::proof_type pr) :
            vk(vk),
            pi(pi), pr(pr) {};
    };

    static inline std::vector<chunk_type> process(verifier_data vd) {

        std::size_t g1_size = modulus_chunks * 3 * CurveType::g1_type::underlying_field_type::arity;
        std::size_t g2_size = modulus_chunks * 3 * CurveType::g2_type::underlying_field_type::arity;
        std::size_t std_size_t_size = 4;

        std::size_t gt_size = modulus_chunks * CurveType::gt_type::underlying_field_type::arity;

        std::size_t sparse_vector_size = std_size_t_size + vd.vk.gamma_ABC_g1.rest.size() * std_size_t_size +
                                         std_size_t_size + vd.vk.gamma_ABC_g1.rest.values.size() * g1_size +
                                         std_size_t_size;

        std::size_t verification_key_size = gt_size + g2_size + g2_size + g1_size + sparse_vector_size;
        std::size_t primary_input_size = std_size_t_size + vd.pi.size() * modulus_chunks;
        std::size_t proof_size = g1_size + g2_size + g1_size;

        std::vector<chunk_type> output(2 * (verification_key_size + primary_input_size + proof_size));

        typename std::vector<chunk_type>::iterator write_iter = output.begin();

        verification_key_process(vd.vk, write_iter);

        primary_input_process(vd.pi, write_iter);

        proof_process(vd.pr, write_iter);

        return output;
    }

    static inline std::vector<chunk_type> process(typename scheme_type::verification_key_type vk,
                                                  typename scheme_type::primary_input_type pi,
                                                  typename scheme_type::proof_type pr) {

        return process(verifier_data(vk, pi, pr));
    }

    static inline std::vector<chunk_type> process(typename scheme_type::verification_key_type vk) {

        std::size_t g1_size = modulus_chunks * 3 * CurveType::g1_type::underlying_field_type::arity;
        std::size_t g2_size = modulus_chunks * 3 * CurveType::g2_type::underlying_field_type::arity;
        std::size_t std_size_t_size = 4;

        std::size_t gt_size = modulus_chunks * CurveType::gt_type::underlying_field_type::arity;

        std::size_t sparse_vector_size =
            std_size_t_size + vk.gamma_ABC_g1.rest.size() * std_size_t_size + std_size_t_size +
            vk.gamma_ABC_g1.rest.values.size() * g1_size + std_size_t_size;

        std::size_t verification_key_size =
            gt_size + g2_size + g2_size + g1_size + sparse_vector_size;

        std::vector<chunk_type> output(2 * verification_key_size);

        typename std::vector<chunk_type>::iterator write_iter = output.begin();

        verification_key_process(vk, write_iter);

        return output;
    }

    static inline std::vector<chunk_type> process() {

        return process(verifier_data());
    }
};

template<typename CurveType, typename OutputIterator>
void pack_tvm(typename r1cs_gg_ppzksnark<CurveType>::verification_key_type vk,
              typename r1cs_gg_ppzksnark<CurveType>::primary_input_type pi,
              typename r1cs_gg_ppzksnark<CurveType>::proof_type pr,
              OutputIterator out) {

    using curve_type = CurveType;
    using field_type = typename curve_type::scalar_field_type;
    using scheme_type = r1cs_gg_ppzksnark<CurveType>;

    using chunk_type = std::uint8_t;

    std::vector<chunk_type> vergrth16_byteblob = verifier_data_to_bits<scheme_type>::process(vk, pi, pr);
    std::copy(vergrth16_byteblob.begin(), vergrth16_byteblob.end(), out);
}

template<typename CurveType>
void export_vergrth16_data_to_file(typename r1cs_gg_ppzksnark<CurveType>::verification_key_type vk,
                                   string pathToFile) {
  
  using curve_type = CurveType;
  using field_type = typename curve_type::scalar_field_type;
  using scheme_type = r1cs_gg_ppzksnark<CurveType>;

  using chunk_type = std::uint8_t;

  ofstream vergrth16_data_file;
  vergrth16_data_file.open(pathToFile);

  std::vector<chunk_type> vergrth16_byteblob = verifier_data_to_bits<scheme_type>::process(vk);

  for(std::size_t i=0; i<vergrth16_byteblob.size(); i++) {
    vergrth16_data_file << vergrth16_byteblob[i];
  }

  vergrth16_data_file.close();
}

#endif    // CRYPTO3_R1CS_GG_PPZKSNARK_TYPES_TVM_MARSHALLING_HPP