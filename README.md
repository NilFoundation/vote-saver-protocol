# [Jens Groth Construction](https://eprint.iacr.org/2016/260.pdf) Proof Verification Example

This example is a simple contract which allows to verify Groth16 zk-SNARK proof.

## Methods
This contract has four methods.
* `verification::constructor()` - method run on the contract's deploy.
* `bool verification::verify(slice proof)` - proof packed into a slice with an
    inner format defined as follows.

## Input format

zk-SNARK verifier `slice proof` argument contains of 3 parts packed together:
* `verification_key_type vk`
* `primary_input_type primary_input`
* `proof_type proof`

Type requirements for those are described in the [Groth16 zk-SNARK policy](https://github.com/NilFoundation/crypto3-zk/blob/master/include/nil/crypto3/zk/snark/proof_systems/ppzksnark/r1cs_gg_ppzksnark.hpp)

Byte vector assumes to be byte representation of all the underlying data types, 
recursively unwrapped to Fp field element and integral `std::size_t` values. 
All the values should be putted in the same order the recursion calculated.
