# TON Zero-Knowledge Voting Protocol.

This repository implements [SAVER](https://eprint.iacr.org/2019/1270) voting protocol.

## Building

Requirements: Boost >= 1.74.

```shell
git clone --recursive git@github.com:NilFoundation/ton-voting-protocol.git contest && cd contest
mkdir build && cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
make cli
```

## Usage

Let's consider voting session consisting of the session administrator and 4 voters.

Consider that their accounts have enough balances to proceed with this protocol.

### Building cli
Cli is used to generate R1CS, CRS, zk-SNARK proofs, ElGamal keys, execute encryption, decryption, proofs creation, (de)serialize generated data and other operations, required for the voting protocol execution.
To build cli run following command:
```sh
mkdir build
cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make cli
```

### Generation
First phase, processed by the administrator, executed using cli with encrypted_input_mode flag:
```sh
./cli --mode encrypted_input
```
At the moment cli generates data both for administrator and voters. It's not the case for real application, and could be used only for demonstration purposes.

After executing this command multiple binary files will be generated. To process voting protocol following files are needed:
- ```verification_key0.bin``` - zk-SNARK verification key, used by administrator to initialize its lscs.
- ```verification_input{i}.bin``` - contain constructed ballots of the voters (where ```i``` - voter's index). It consists of zk-SNARK proof, zk-SNARK verification key, encrypted ballot, session id, serial number of the ballot and merkle tree root hash, built upon voters public keys. Again in real application voter would construct such blob manually, receiving zk-SNARK keys, session id and merkle tree root hash from the administrator, but for demonstration purposes generation was simplified.

Also voters' public key will be printed into the terminal, and could be copied to initialize voters' lscs.

To execute requests to the rfld network generated binary data should be converted into the hexstring representation. It could be done using following python script:
```python
 with open(verification_input0.bin, 'rb') as f:
    hexdata = binascii.hexlify(f.read())
    hexdata_str = '01' + hexdata.decode("ascii")
    print(hexdata_str)

 with open(verification_key0.bin, 'rb') as f:
    hexdata = binascii.hexlify(f.read())
    hexdata_str = hexdata.decode("ascii")
    print(hexdata_str)
```
First byte `01` when working with ballot blob file required for the correct work of the TVM, so it should not be missed.

### Building In-TVM Application
Following instruction will cover work with rfld network and interaction with in-TVM logic. To execute these operation 
following forks should be used:
- [`tonos-cli`](https://github.com/NilFoundation/ton-tonos-cli/tree/2-groth16-verification-encrypted-input-mode)
- [`solc`](https://github.com/NilFoundation/tvm-solidity)
- [`tvm-linker`](https://github.com/NilFoundation/tvm-linker/tree/1-vergrth16)

There are two lscs implementing voting protocol logic:
- voting_admin.sol
- voting_voter.sol

To complie them run the following commands:
 ```sh
 cd ./share/tvm
 ./build.sh voting_admin
 ./build.sh voting_voter
 mkdir keys
 mkdir genaddr-output
 ./genaddr.sh voting_admin
 ./genaddr.sh voting_voter 0
 ./genaddr.sh voting_voter 1
 # and so on, how much voters you need
 ```
Following interaction with rfld network considered to be executed from the same directory.

### Admin Deployment:
```sh
tonos-cli deploy --abi voting_admin.abi.json --sign keys/voting_admin.keys.json voting_admin.tvc '{}'
```

### zk-SNARK pre-initialization
Admin pre-initialize voting context, namely upload zk-SNARK proving and verification keys. These keys could be large, so several calls of the ```update_crs``` function may be required. There is also a function ```reset_crs``` allowing to begin uploading again.
```sh
tonos-cli call 0:5c691b758a85d88035e9eb18b6713e4706972474b5e3e642213cfa499c1b7510 update_crs '{"pk":"<crs_proving_key>", "vk":"<crs_verification_key>"}' --abi voting_admin.abi.json --sign keys/voting_admin.keys.json

tonos-cli call 0:5c691b758a85d88035e9eb18b6713e4706972474b5e3e642213cfa499c1b7510 reset_crs '{}' --abi voting_admin.abi.json --sign keys/voting_admin.keys.json
```

### Admin initialize voting session:
```sh
tonos-cli call 0:5c691b758a85d88035e9eb18b6713e4706972474b5e3e642213cfa499c1b7510 init_voting_session '{"eid":"<session id>","pk_eid":"<ElGamal public key>","vk_eid":"<ElGamal verification key>","voters_addresses":["0:df676530c241ff7e00796bf616aaf57a089df0521af0913c530c09af8b1852c3","0:cf8f119a7e4fd4f76fe499acd36e73745c497dba684755fed9361d86645ba50c","0:c2ce805ed58704653643f7e20e457d8ce4f47128017846cf8caadbd194ff6cac","0:21d8141bf87804445a4823c6c90596f6cceb82a748422b08cf51cc65e8c9437e"],"rt":"<root hash of the merkle tree constructed upon voters public keys>"}' --abi voting_admin.abi.json --sign keys/voting_admin.keys.json
```
Each call to the function ```init_voting_session``` will initialize a new session completing the previous.

### Voters deployment:
```sh
tonos-cli deploy --abi voting_voter.abi.json --sign keys/voting_voter0.keys.json voting_voter.tvc '{"pk":"010203", "admin":"0:5c691b758a85d88035e9eb18b6713e4706972474b5e3e642213cfa499c1b7510"}'
# ...the same for other voters
```
During deployment voters using constructor argument ```admin``` specify administrator address, which hold voting session. Also they specify their public keys via ```pk``` (this is not deployment key from ```voting_voter0.keys.json```, it's abstract public key required by the Saver protocol and it's used to construct merkle tree).

### Votes uploading and committing
Voters upload their encrypted proved and already !rerandomized! ballots:
```sh
tonos-cli call 0:df676530c241ff7e00796bf616aaf57a089df0521af0913c530c09af8b1852c3 update_ballot '{"vi":"<ballot blob which consists of: proof, crs vkey, ElGamal pubkey, encrypted ballot, session id, serial number and merkle tree root hash>"}' --abi voting_voter.abi.json --sign keys/voting_voter0.keys.json
# ...the same for other voters
```
Input blob could be large, so several calls of the ```update_ballot``` function may be required. There is also a function ```reset_ballot``` allowing to begin uploading again.

Voters commit their ballots:
```sh
tonos-cli call 0:df676530c241ff7e00796bf616aaf57a089df0521af0913c530c09af8b1852c3 commit_ballot '{"proof_end":193,"ct_begin":35273,"eid_begin":35721,"sn_begin":37769,"sn_end":45929 }' --abi voting_voter.abi.json --sign keys/voting_voter0.keys.json
```
During this step zk-SNARK verification of the input blob is processed. Input parameters index input blob, which should have strict format, mentioned above, otherwise zk-SNARK verification will return false result. When all checks in ```commit_ballot``` finish successfully, internal message to admin is sent, containing session id and serial number from the ballot blob. When all checks on the administrator side finish another internal message to the voter's callback function will be sent, containing statis of the administrator checks. If all checks are successful voter's ```m_is_vote_accepted``` flag is set to ```true``` (it could be get by the  ```is_vote_accepted``` function call to the voter's lscs). Also this voter will be marked as commited on the administrator side. Warning: every successful call to the functions ```reset_ballot``` or ```update_ballot``` will decommit voter's vote on the voter and administrator sides, so ```commit_ballot``` should be called again.

When all voters commit their ballots administrator downloads their encrypted ballot messages by calling to the ```get_ct``` function of voters' lscs, forms aggregated cipher text and uploads it by calling to the ```update_tally```. After that administrator forms and uploads voting result (namely, decrypted aggregated cipher text) and decryption proof also using ```update_tally``` function. And finally administrator call ```commit_tally``` to make it possible for the voters to get this data by calling to the ```get_ct_sum```, ```get_m_sum```, ```get_dec_proof``` and then verify decryption using proof.

Administrator checks commit statuses of the voters calling to the ```get_voters_statuses```. Example call:
```sh
tonos-cli call 0:5c691b758a85d88035e9eb18b6713e4706972474b5e3e642213cfa499c1b7510 get_voters_statuses '{}' --abi voting_admin.abi.json --sign keys/voting_admin.keys.json
```
Example answer:
```sh
#...
MessageId: 72562068c2dd4f94b8fb38d8a484bec7ae2ca8917463a5da870eca8903aa7363
Succeeded.
Result: {
  "value0": {
    "0:21d8141bf87804445a4823c6c90596f6cceb82a748422b08cf51cc65e8c9437e": false,
    "0:c2ce805ed58704653643f7e20e457d8ce4f47128017846cf8caadbd194ff6cac": false,
    "0:cf8f119a7e4fd4f76fe499acd36e73745c497dba684755fed9361d86645ba50c": false,
    "0:df676530c241ff7e00796bf616aaf57a089df0521af0913c530c09af8b1852c3": true
  }
}
```