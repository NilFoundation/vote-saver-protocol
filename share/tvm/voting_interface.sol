pragma ton-solidity >= 0.30.0;

interface IVoter {
}

interface IAdmin {
    function check_ballot(bytes, bytes) external responsible returns (bool);
    function uncommit_ballot() external responsible returns(bool);
}

library SharedStructs {
    struct CRS {
        bytes pk;
        bytes vk;
    }

    struct Ballot {
        bytes vi;
        uint32 ct_begin;
        uint32 eid_begin;
        uint32 sn_begin;
        uint32 sn_end;
    }

    struct SessionState {
        uint voters_number;
        bytes pk_eid;
        bytes vk_eid;
        mapping(address => bool) voter_map_accepted;
        bytes rt;
    }

    function cmp_bytes(bytes a, bytes b) public returns (bool) {
        return a.length == b.length && a.toSlice().compare(b.toSlice()) == 0;
    }
}