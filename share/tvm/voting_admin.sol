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
        require(msg.pubkey() != 0, 104);
        require(m_session_state.voter_map_pubkey.exists(msg.sender), 105);
        require(m_session_state.voter_map_pubkey.at(msg.sender) == msg.pubkey(), 106);
        _;
    }

    function init_voting_session(bytes eid, bytes pk_eid, bytes vk_eid, address[] voters_addresses, uint256[] voters_pubkeys, bytes rt) public checkOwnerAndAccept returns (bool) {
        if (voters_addresses.length <= 0) {
            return false;
        }
        if (voters_addresses.length != voters_pubkeys.length) {
            return false;
        }
        if (!m_all_eid.add(eid, null)) {
            // voting session with such eid was initialized already
            return false;
        }

        m_eid = eid;
        SharedStructs.SessionState session_init_state;
        session_init_state.pk_eid = pk_eid;
        session_init_state.vk_eid = vk_eid;
        session_init_state.rt = rt;
        for (uint i = 0; i < voters_addresses.length; i++) {
            address vote_address = voters_addresses[i];
            session_init_state.voter_map_pubkey.add(vote_address, voters_pubkeys[i]);
            session_init_state.voter_map_ballot.add(vote_address, null);
        }
        session_init_state.voters_number = voters_addresses.length;
        m_session_state = session_init_state;
        return true;
    }

    function send_ballot(bytes eid, SharedStructs.Ballot ballot) public checkSenderIsVoter responsible override returns (bool) {
        if (!SharedStructs.cmp_bytes(eid, m_eid)) {
            // incorrect session id
            return false;
        }
        if (m_session_state.voter_map_ballot.at(msg.sender).hasValue()) {
            // already voted
            return false;
        }
        if (!m_all_sn.add(ballot.sn, null)) {
            // sn already sent
            return false;
        }
        // TODO: vergrth16
        // TODO: rerand
        if (!m_session_state.voter_map_ballot.replace(msg.sender, ballot)) {
            // unexpected error happened
            return false;
        }
        return true;
    }

    function get_vote_internal(bytes eid, address sender) private view returns (bool, bytes, bytes, bytes) {
        if (!SharedStructs.cmp_bytes(eid, m_eid)) {
            // incorrect session id
            return (false, "", "", "");
        }
        if (!m_session_state.voter_map_ballot.exists(sender)) {
            // not eligible voter
            return (false, "", "", "");
        }
        if (!m_session_state.voter_map_ballot[sender].hasValue()) {
            // not voted yet
            return (false, "", "", "");
        }

        SharedStructs.Ballot ballot = m_session_state.voter_map_ballot[sender].get();
        return (true, ballot.sn, ballot.proof, ballot.ct);
    }

    function get_voter_vote(address sender) public view checkOwnerAndAccept returns (bool, bytes, bytes, bytes) {
        return get_vote_internal(m_eid, sender);
    }

    function get_vote(bytes eid) public checkSenderIsVoter responsible override returns (bool, bytes, bytes, bytes) {
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
