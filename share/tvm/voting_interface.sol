pragma ton-solidity >= 0.30.0;

interface IVoter {
}

interface IAdmin {
    function check_ballot(bytes, bytes) external responsible returns (int32);
    function uncommit_ballot() external responsible returns(int32);
}

library SharedStructs {
    struct CRS {
        bytes pk;
        bytes vk;
    }

    struct Ballot {
        bytes vi;
        uint32 proof_end;
        uint32 ct_begin;
        uint32 ct_end;
        uint32 eid_begin;
        uint32 sn_begin;
        uint32 rt_begin;
    }

    struct SessionState {
        uint voters_number;
        bytes pk_eid;
        bytes vk_eid;
        address[] voters_addresses;
        mapping(address => bool) voter_map_accepted;
        bytes rt;
        bytes[] ct_sum;
        bytes[] m_sum;
        bytes[] dec_proof;
    }

    function cmp_bytes(bytes a, bytes b) public returns (bool) {
        return a.length == b.length && a.toSlice().compare(b.toSlice()) == 0;
    }
}