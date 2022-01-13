pragma ton-solidity >= 0.30.0;

import "voting_interface.sol";

contract SaverAdmin is IAdmin {
    constructor(bytes pk, bytes vk) public {
        require(tvm.pubkey() != 0, 101);
        require(msg.pubkey() == tvm.pubkey(), 102);
        tvm.accept();

        m_crs.pk = pk;
        m_crs.vk = vk;
    }

    modifier checkOwnerAndAccept {
        require(msg.pubkey() == tvm.pubkey(), 103);
        tvm.accept();
        _;
    }

    modifier checkSenderIsVoter {
        require(m_session_state.voter_map_ballot.exists(msg.sender), 104);
        _;
    }

    function init_voting_session(bytes eid, bytes pk_eid, bytes vk_eid, address[] voters_addresses, bytes rt) public checkOwnerAndAccept {
        require(voters_addresses.length > 0, 105);
        // voting session with such eid was initialized already
        require(m_all_eid.add(eid, null), 106);

        m_eid = eid;
        SharedStructs.SessionState session_init_state;
        session_init_state.pk_eid = pk_eid;
        session_init_state.vk_eid = vk_eid;
        session_init_state.rt = rt;
        for (uint i = 0; i < voters_addresses.length; i++) {
            session_init_state.voter_map_ballot.add(voters_addresses[i], null);
        }
        session_init_state.voters_number = voters_addresses.length;
        m_session_state = session_init_state;
    }

    function send_ballot(bytes eid, SharedStructs.Ballot ballot, SharedStructs.Ballot ballot_rerand) public checkSenderIsVoter responsible override returns (uint8) {
        if (!SharedStructs.cmp_bytes(eid, m_eid)) {
            // incorrect session id
            return 2;
        }
        if (m_session_state.voter_map_ballot.at(msg.sender).hasValue()) {
            // already voted
            return 3;
        }
        if (!SharedStructs.cmp_bytes(ballot.sn, ballot_rerand.sn)) {
            // sn are not equal
            return 4;
        }
        if (SharedStructs.cmp_bytes(ballot.ct, ballot_rerand.ct)) {
            // ballot is not rerandomized
            return 5;
        }
        if (SharedStructs.cmp_bytes(ballot.proof, ballot_rerand.proof)) {
            // ballot is not rerandomized
            return 6;
        }
        if (m_all_sn.exists(ballot.sn)) {
            // sn already sent
            return 7;
        }

        // TODO: vergrth16
        bytes verification_input;
        verification_input.append(ballot.proof);
        verification_input.append(m_crs.vk);
        verification_input.append(m_session_state.pk_eid);
        verification_input.append(ballot.ct);
        verification_input.append(m_eid);
        verification_input.append(ballot.sn);
        verification_input.append(m_session_state.rt);
//        if (!tvm.vergrth16(verification_input)) {
//            return 8;
//        }

        if (!m_session_state.voter_map_ballot.replace(msg.sender, ballot_rerand)) {
            // unexpected error happened
            return 9;
        }
        if (!m_all_sn.add(ballot.sn, null)) {
            // unexpected error happened
            return 10;
        }
        return 0;
    }

    function get_vote_internal(bytes eid, address sender) private view returns (optional(SharedStructs.Ballot)) {
        if (!SharedStructs.cmp_bytes(eid, m_eid)) {
            // incorrect session id
            return null;
        }
        if (!m_session_state.voter_map_ballot.exists(sender)) {
            // not eligible voter
            return null;
        }
        if (!m_session_state.voter_map_ballot[sender].hasValue()) {
            // not voted yet
            return null;
        }

        return m_session_state.voter_map_ballot[sender].get();
    }

    function get_voter_vote(address voter_addr) public view checkOwnerAndAccept returns (optional(SharedStructs.Ballot)) {
        return get_vote_internal(m_eid, voter_addr);
    }

    function get_vote(bytes eid) public checkSenderIsVoter responsible override returns (optional(SharedStructs.Ballot)) {
        return get_vote_internal(eid, msg.sender);
    }

    function get_all_ct() public view checkOwnerAndAccept returns (bool, bytes[]) {
        bytes[] all_ct = new bytes[](m_session_state.voters_number);

        uint i = 0;
        for ((, optional(SharedStructs.Ballot) ballot) : m_session_state.voter_map_ballot) {
            if (!ballot.hasValue()) {
                // not all voters voted
                bytes[] empty_array;
                return (false, empty_array);
            }
            all_ct[i] = ballot.get().ct;
        }
        return (true, all_ct);
    }

    bytes public m_eid;
    SharedStructs.CRS public m_crs;
    SharedStructs.SessionState public m_session_state;
    mapping(bytes => optional(bool))  m_all_eid;
    mapping(bytes => optional(bool))  m_all_sn;
}
