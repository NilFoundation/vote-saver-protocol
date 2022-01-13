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
        require(m_session_state.voter_map_accepted.exists(msg.sender), 104);
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
            session_init_state.voter_map_accepted.add(voters_addresses[i], false);
        }
        session_init_state.voters_number = voters_addresses.length;
        m_session_state = session_init_state;
    }

    function check_ballot(bytes eid, bytes sn) external checkSenderIsVoter responsible override returns (bool) {
        if (!SharedStructs.cmp_bytes(m_eid, eid)) {
            // incorrect session id
            m_session_state.voter_map_accepted.replace(msg.sender, false);
        }
        else if (!m_all_sn.add(sn, null)) {
            // such sn already sent
            m_session_state.voter_map_accepted.replace(msg.sender, false);
        }
        else {
            m_session_state.voter_map_accepted.replace(msg.sender, true);
        }
        return m_session_state.voter_map_accepted.at(msg.sender);
    }

    function get_session_data() external checkSenderIsVoter responsible override returns (bytes, bytes, bytes) {
        return (m_crs.vk, m_session_state.pk_eid, m_session_state.rt);
    }

    function get_voter_ct(address voter_addr) public view checkOwnerAndAccept {
        require(m_session_state.voter_map_accepted.exists(voter_addr), 107);
        require(m_session_state.voter_map_accepted.at(voter_addr), 108);
        m_recieved_ct = null;
        IVoter(voter_addr).get_ct{callback: on_get_ct}();
    }

    function get_voter_status(address voter_addr) public view checkOwnerAndAccept returns (bool) {
        require(m_session_state.voter_map_accepted.exists(voter_addr), 109);
        return m_session_state.voter_map_accepted.at(voter_addr);
    }

    function on_get_ct(optional(bytes) ct) public checkSenderIsVoter {
        m_recieved_ct = ct;
    }

    bytes public m_eid;
    SharedStructs.CRS public m_crs;
    SharedStructs.SessionState public m_session_state;
    optional(bytes) public m_recieved_ct;
    mapping(bytes => optional(bool))  m_all_eid;
    mapping(bytes => optional(bool))  m_all_sn;
}
