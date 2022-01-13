pragma ton-solidity >= 0.30.0;

interface IVoter {
    function get_ct() external responsible returns (optional(bytes));
}

interface IAdmin {
    function get_session_data() external responsible returns (bytes, bytes, bytes);
    function check_ballot(bytes, bytes) external responsible returns (bool);
}

library SharedStructs {
    struct CRS {
        bytes pk;
        bytes vk;
    }

    struct Ballot {
        bytes eid;
        bytes sn;
        bytes proof;
        bytes ct;
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