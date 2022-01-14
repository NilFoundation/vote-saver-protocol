pragma ton-solidity >= 0.30.0;

import "voting_interface.sol";

contract SaverAdmin is IAdmin {
    constructor() public {
        require(tvm.pubkey() != 0, 101);
        require(msg.pubkey() == tvm.pubkey(), 102);
        tvm.accept();
    }

    modifier checkOwnerAndAccept {
        require(msg.pubkey() == tvm.pubkey(), 103);
        tvm.accept();
        _;
    }

    modifier checkSenderIsVoter {
        require(m_session_state.voter_map_accepted.exists(msg.sender), 104);
        tvm.accept(); // TODO
        _;
    }

    function update_crs(bytes pk, bytes vk) public checkOwnerAndAccept {
        m_crs.pk.append(pk);
        m_crs.vk.append(vk);
    }

    function reset_crs() public checkOwnerAndAccept {
        m_crs.pk = hex"";
        m_crs.vk = hex"";
    }

    function reset_context() public checkOwnerAndAccept {
        m_session_state.voters_number = 0;
        m_session_state.pk_eid = hex"";
        m_session_state.vk_eid = hex"";
        m_session_state.rt = hex"";
        mapping(address => bool) m1;
        m_session_state.voter_map_accepted = m1;

        m_eid = hex"";

        mapping(bytes => optional(bool)) m2;
        mapping(bytes => optional(bool)) m3;
        m_all_eid = m2;
        m_all_sn = m3;
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

    function uncommit_ballot() external checkSenderIsVoter responsible override returns (bool) {
        m_session_state.voter_map_accepted.replace(msg.sender, false);
        return true;
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

    function get_voter_status(address voter_addr) public view checkOwnerAndAccept returns (bool) {
        require(m_session_state.voter_map_accepted.exists(voter_addr), 109);
        return m_session_state.voter_map_accepted.at(voter_addr);
    }

    function reset_tally() public checkOwnerAndAccept {
        m_session_state.m_sum = hex"";
        m_session_state.dec_proof = hex"";
    }

    function update_tally(bytes m_sum, bytes dec_proof) public checkOwnerAndAccept {
        m_session_state.m_sum.append(m_sum);
        m_session_state.dec_proof.append(dec_proof);
    }

    function get_voters_addresses() public view returns (address[]) {
        tvm.accept();
        address[] ret;
        for ((address addr,) : m_session_state.voter_map_accepted) {
            ret.push(addr);
        }
        return ret;
    }

    bytes public m_eid;
    SharedStructs.CRS public m_crs;
    SharedStructs.SessionState public m_session_state;
    mapping(bytes => optional(bool))  m_all_eid;
    mapping(bytes => optional(bool))  m_all_sn;
}
