# Voting Protocol
## Step by step tutorial

Voting Protocol is based on the [Saver](https://eprint.iacr.org/2019/1270) protocol.

It has following features:
- foo1
- foo2


## Protocol Phases

Let's consider voting session consisting of the session administrator and 4 voters.

Participants will deploy their lscs in the network with the following addresses:

Admin:
```0:5c691b758a85d88035e9eb18b6713e4706972474b5e3e642213cfa499c1b7510```
Voter0:
```0:df676530c241ff7e00796bf616aaf57a089df0521af0913c530c09af8b1852c3```
Voter1:
```0:cf8f119a7e4fd4f76fe499acd36e73745c497dba684755fed9361d86645ba50c```
Voter2:
```0:c2ce805ed58704653643f7e20e457d8ce4f47128017846cf8caadbd194ff6cac```
Voter3:
```0:21d8141bf87804445a4823c6c90596f6cceb82a748422b08cf51cc65e8c9437e```

Also consider that they have enough balances to proceed with this protocol.

Admin deployment:
```sh
tonos-cli deploy --abi voting_admin.abi.json --sign keys/voting_admin.keys.json voting_admin.tvc '{}'
```

Admin pre-initialize voting context, namely upload zk-SNARK proving and verification keys. These keys could be large, so several calls of the ```update_crs``` function may be required. There is also a function ```reset_crs``` allowing to begin uploading again.
```sh
tonos-cli call 0:5c691b758a85d88035e9eb18b6713e4706972474b5e3e642213cfa499c1b7510 update_crs '{"pk":"<crs_proving_key>", "vk":"<crs_verification_key>"}' --abi voting_admin.abi.json --sign keys/voting_admin.keys.json

tonos-cli call 0:5c691b758a85d88035e9eb18b6713e4706972474b5e3e642213cfa499c1b7510 reset_crs '{}' --abi voting_admin.abi.json --sign keys/voting_admin.keys.json
```

Admin initialize voting session:
```sh
tonos-cli call 0:5c691b758a85d88035e9eb18b6713e4706972474b5e3e642213cfa499c1b7510 init_voting_session '{"eid":"<session id>","pk_eid":"<ElGamal public key>","vk_eid":"<ElGamal verification key>","voters_addresses":["0:df676530c241ff7e00796bf616aaf57a089df0521af0913c530c09af8b1852c3","0:cf8f119a7e4fd4f76fe499acd36e73745c497dba684755fed9361d86645ba50c","0:c2ce805ed58704653643f7e20e457d8ce4f47128017846cf8caadbd194ff6cac","0:21d8141bf87804445a4823c6c90596f6cceb82a748422b08cf51cc65e8c9437e"],"rt":"<root hash of the merkle tree constructed upon voters public keys>"}' --abi voting_admin.abi.json --sign keys/voting_admin.keys.json
```
Each call to the function ```init_voting_session``` will initialize a new session completing the previous.

Voters deployment:
```sh
tonos-cli deploy --abi voting_voter.abi.json --sign keys/voting_voter0.keys.json voting_voter.tvc '{"pk":"010203", "admin":"0:5c691b758a85d88035e9eb18b6713e4706972474b5e3e642213cfa499c1b7510"}'
# ...the same for other voters
```
During deployment voters using constructor argument ```admin``` specify administrator address, which hold voting session. Also they specify their public keys via ```pk``` (this is not deployment key from ```voting_voter0.keys.json```, it's abstract public key required by the Saver protocol and it's used to construct merkle tree).

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
