# TON Proof Verification Protocol Template repository.

One of the exciting recent developments around zk-SNARKs is that it is now possible to verify a zk-SNARK proof in a
lscs (a.k.a. smart contract) on FreeTON. 

Let's see how we can create a Solidity smart contract to generate proofs for that circuit on FreeTON.

## Building

Requirements: Boost >= 1.74.

```shell
git clone --recursive git@github.com:NilFoundation/ton-cryptography-subgovernance-template.git contest && cd contest
mkdir build && cd build
cmake ..
make cli
```

## Building with code optimization

On debug build type, keypair and proof generation can take a long time for big circuits.

To use release build type with -O3 optimization:

```shell
cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
make cli
```  

**To update** ```git submodule update --init --recursive```


## Verification instruction VERGRTH16 input creation

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

When running the executable `cli` from within the build directory two files will be created: `proof_data` and `vk_data`
containing the corresponding data in the form of byteblobs.


## Building  solidity contracts

You need to use a **solc compiler** and **tvm linker** with support for these instructions:

- [solidity compiler fork](https://github.com/nilfoundation/tvm-solidity)

- [linker fork](https://github.com/NilFoundation/tvm-linker)

These forks **need to be built using instructions** from repo.
*You will need `Boost` with `Boost.Filesystem` module to build them.* 

After compilation you will have 2 files: `solc` (solidity compiler) and `tvm_linker` (linker). 

To use these versions through `tondev`: 

- you need to **put these files in the directory** `~/.tondev/solidity`/ 

-  give execution rights (`chmod +x`) to these files *(otherwise `tondev` will crash)*


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


## Deploy instructions:

### Creating a `SetcodeMultisigWallet` wallet:

[Full instruction is here](https://github.com/tonlabs/ton-labs-contracts/tree/master/solidity/safemultisig#install-through-tondev)

1. Add ZKP-ready FLD network to `tondev`:
`tondev network add fld gql.custler.net`
2. Create / Add your wallet via `tondev signer` and save your `<YOU_SIGNER_PUBLIC_ADDRESS>`
3. Download wallet files:
```bash 
wget https://raw.githubusercontent.com/tonlabs/ton-labs-contracts/master/solidity/setcodemultisig/SetcodeMultisigWallet.abi.json

wget https://github.com/tonlabs/ton-labs-contracts/raw/master/solidity/setcodemultisig/SetcodeMultisigWallet.tvc
```
4. Get wallet address:
    `tondev contract info SetcodeMultisigWallet.abi.json -n fld `

  It should be printed as:
  > Address:   0:<address> (calculated from TVC and signer public)

5. Request test token from Jury (Ask to fund this address someone in related telegram group) to `<address>`
  - ... Wait for it ...
  -  now check your balance: `tondev contract info -a 0:<address> -n fld | grep Balance`
6. Deploy wallet:
    `tondev contract deploy SetcodeMultisigWallet.abi.json constructor -n fld -i owners:"[0x<YOU_SIGNER_PUBLIC_ADDRESS>]",reqConfirms:1`

You will get something like this:
>Deploying...
>Contract has deployed at address: 0:<address>

- Profit!

Now you have wallet and can deploy smart contracts. 

Let's go to deployment step!

## Deployment

### Moving proof:
1. Transform binary proof file to hex format for usage with a tondev tool and copy it to a smart contract folder:
`cat proof | xxd -p | tr -d '\n' > ../examples/lscs/solidity/proof.hex`
2. cd to smart contract folder
`cd ../examples/lscs/solidity/`

### Deploy smart contract

1. Compile smart contract
`tondev sol compile verification.sol `
2. Get address of a contract:
`tondev contract info verification.abi.json`
3. Send tokens to address of a contract *(for deploy you will need 10 tokens)*:
`tondev contract run SetcodeMultisigWallet.abi.json submitTransaction -n nil -i dest:<CONTRACT_ADDRESS>,value:10000000000,bounce:false,allBalance:false,payload:""`
4. Deploy smart contract:
`tondev contract deploy verification.abi -n nil`
5. Verify proof on chain:
`tondev contract run verification.abi.json verify -p -i proof:$(cat proof.hex) --network nil`


## Tests
Put your tests in a `test` folder.
1. `cd build`
2. Build tests:
`cmake .. -DDBUILD_TESTS=1`
`make circuit_test`
3. Run tests: `test/circuit_test`
