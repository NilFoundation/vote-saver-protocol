# TON Proof Verification Contest.

One of the exciting recent developments around zk-SNARKs is that it is now possible to verify a zk-SNARK proof in a
lscs (a.k.a. smart contract) on FreeTON. This opens up the possibility of private transactions and the ability to verify
large computations on the blockchain.

Let's see how we can create a Solidity smart contract to generate proofs for that circuit on FreeTON.

## How to create verification instruction VERGRTH16 input

To create `VERGRTH16` instruction input you need to represent the 'what you want to prove' in the form of a constraint
system using =nil;Crypto3 [Blueprint](https://github.com/NilFoundation/crypto3-blueprint) module and then prove it using
=nil;Crypto3
[ZK](https://github.com/NilFoundation/crypto3-zk) module. Then you can use byte-serialized output of the 'prove'
function as input to the instruction in your lscs (a.k.a. smart contract).

The =nil;Crypto3 Blueprint zk-SNARK library is a powerful library for defining circuits, generating & verifying proofs.
It can be hard to get a sense of how to use it in practice, so please
follow [the tutorial](https://github.com/NilFoundation/crypto3-blueprint) providing a sense of the high-level components
of =nil;Crypto3 Blueprint and how to use it concretely, as well as how to connect the proofs to FreeTON lscs.

## Serializing verification keys and proofs

If you have runned
the [generate](https://github.com/NilFoundation/crypto3-zk/blob/master/include/nil/crypto3/zk/snark/algorithms/generate.hpp)
and [prove](https://github.com/NilFoundation/crypto3-zk/blob/master/include/nil/crypto3/zk/snark/algorithms/prove.hpp)
algorithms for Groth16, than you have all the data you need. There should
be [verification keys](https://github.com/NilFoundation/crypto3-zk/blob/master/include/nil/crypto3/zk/snark/schemes/ppzksnark/r1cs_gg_ppzksnark/verification_key.hpp)
and [proof](https://github.com/NilFoundation/crypto3-zk/blob/master/include/nil/crypto3/zk/snark/schemes/ppzksnark/r1cs_gg_ppzksnark/proof.hpp)
in the appropriate format.

First we need to extract the verification keys and proofs from
=nil;Crypto3 [Blueprint](https://github.com/NilFoundation/crypto3-blueprint) in a way that can be consumed by Solidity
smart contracts. In the file `cli/src/main.cpp` we demonstrate how to serialize the information from the
objects `r1cs_gg_ppzksnark<bls12<381>>::verification_key_type` and `r1cs_gg_ppzksnark<bls12<381>>::proof_type` and write
that information to a file in the form of field elements that can be interpreted as byteblobs in Solidity.

We won't go into detail here about the meaning of the values `A`, `B`, `C` etc in the proof data but check
out [Vitalik's blog post](https://medium.com/@VitalikButerin/zk-snarks-under-the-hood-b33151a013f6) to learn more. The
main thing to illustrate is that these values are elliptic curve points and hence will be represented by two elements of
the underlying field.

When running the executable `cli` from within the build directory two files will be created: `proof_data` and `vk_data`
containing the corresponding data in the form of byteblobs.

## Using verification keys and proofs in Solidity

We first take a look at the Solidity file `examples/solidity/verifier.sol` which contains the verification contract
code. This file contains the function `verify()`, which stores incoming byteblob and gives it as input for the TVM
instruction.

## `VERGRTH16` usage example

This example is a simple contract which allows to verify Groth16 zk-SNARK proof using TVM.

### Methods

This contract has two methods.

* `verification::constructor()` - method run on the contract's deploy.
* `bool verification::verify(slice proof)` - proof packed into a slice with an inner format defined as follows.

### Input format

zk-SNARK verifier `bytes proof` argument contains of 3 parts packed together:

* `verification_key_type vk`
* `primary_input_type primary_input`
* `proof_type proof`

Type requirements for those are described in
the [Groth16 zk-SNARK policy](https://github.com/NilFoundation/crypto3-zk/blob/master/include/nil/crypto3/zk/snark/schemes/ppzksnark/r1cs_gg_ppzksnark.hpp)

Byte vector assumes to be byte representation of all the underlying data types, recursively unwrapped to Fp field
element and integral `std::size_t` values. All the values should be putted in the same order the recursion calculated.
