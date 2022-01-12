pragma ton-solidity >= 0.30.0;

interface IVoter {
}

interface IAdmin {
    function send_ballot(bytes, SharedStructs.Ballot) external responsible returns (bool);
    // @return (sn, proof, ct)
    function get_vote(bytes) external responsible returns (bool, bytes, bytes, bytes);
}

library SharedStructs {
    struct CRS {
        bytes pk;
        bytes vk;
    }

    struct Ballot {
        bytes sn;
        bytes proof;
        bytes ct;
    }

    struct SessionState {
        uint voters_number;
        bytes pk_eid;
        bytes vk_eid;
        mapping(address => uint256) voter_map_pubkey;
        mapping(address => optional(Ballot)) voter_map_ballot;
        bytes rt;
    }

    function cmp_bytes(bytes a, bytes b) public returns (bool) {
        return a.length == b.length && a.toSlice().compare(b.toSlice()) == 0;
    }
}