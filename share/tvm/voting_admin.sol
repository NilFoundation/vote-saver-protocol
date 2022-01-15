pragma ton-solidity >= 0.30.0;

import "voting_interface.sol";

contract SaverAdmin is IAdmin {
    constructor() public {
        require(tvm.pubkey() != 0, 101);
        require(msg.pubkey() == tvm.pubkey(), 102);
        tvm.accept();
        reset_voter_msg_accepted();
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

    // ============================================
    // Pre-initialization of the zk-SNARK keys
    // ============================================
    function update_crs(bytes pk, bytes vk) public checkOwnerAndAccept {
        reset_context();
        m_crs.pk.append(pk);
        m_crs.vk.append(vk);
    }

    function reset_crs() public checkOwnerAndAccept {
        reset_context();
        m_crs.pk = hex"";
        m_crs.vk = hex"";
    }
    // ============================================

    // ============================================
    // Admin has the possibility to reset history of all voting sessions
    // ============================================
    function reset_context() public checkOwnerAndAccept {
        m_is_tally_committed = false;
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
    // ============================================

    // ============================================
    // Initialization of the new voting session
    // ============================================
    function init_voting_session(bytes eid, bytes pk_eid, bytes vk_eid, address[] voters_addresses, bytes rt) public checkOwnerAndAccept {
        require(voters_addresses.length > 0, 106);
        // voting session with such eid was initialized already
        require(m_all_eid.add(eid, null), 107);

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
        m_is_tally_committed = false;
    }
    // ============================================

    // ============================================
    // Accepting and checking of the votes
    // ============================================
    function check_ballot(bytes eid, bytes sn) external checkSenderIsVoter responsible override returns (int32) {
        m_voter_msg_accepted = 1;
        int32 result_status = 0;
        if (!SharedStructs.cmp_bytes(m_eid, eid)) {
            // incorrect session id
            m_session_state.voter_map_accepted.replace(msg.sender, false);
            result_status = 1;
        }
        else if (!m_all_sn.add(sn, null)) {
            // such sn already sent
            m_session_state.voter_map_accepted.replace(msg.sender, false);
            result_status = 2;
        }
        else {
            m_session_state.voter_map_accepted.replace(msg.sender, true);
        }
        return result_status;
    }
    // ============================================

    // ============================================
    // Any change of the participant's vote will lead to the reset of its state
    // and require another call of the check_ballot function
    // ============================================
    function uncommit_ballot() external checkSenderIsVoter responsible override returns (int32) {
        m_voter_msg_accepted = 2;
        m_session_state.voter_map_accepted.replace(msg.sender, false);
        return 0;
    }
    // ============================================

    // ============================================
    // Potential problem: malicious administrator could begin tally phase before all voters committed their ballots.
    // So voters could believe that everyone's votes were considered but in reality it's not the case.
    // Permissibility of such possibilities depends on requirements specification for the application of the voting
    // system in production (how much we trust administrator, for example).
    // Possible solution:
    // ============================================
//    function is_tally_ready() private view returns(bool) {
//        for ((, bool voter_status) : m_session_state.voter_map_accepted) {
//            if (!voter_status) {
//                return false;
//            }
//        }
//        return true;
//    }
    // ============================================

    // ============================================
    // Final phase of the voting
    // ============================================
    function reset_tally() public checkOwnerAndAccept {
        // See description above
//        require(is_tally_ready(), 108);
        m_is_tally_committed = false;
        m_session_state.ct_sum = hex"";
        m_session_state.m_sum = hex"";
        m_session_state.dec_proof = hex"";
    }

    function update_tally(bytes ct_sum, bytes m_sum, bytes dec_proof) public checkOwnerAndAccept {
        // See description above
//        require(is_tally_ready(), 108);
        m_is_tally_committed = false;
        m_session_state.ct_sum.append(ct_sum);
        m_session_state.m_sum.append(m_sum);
        m_session_state.dec_proof.append(dec_proof);
    }

    function commit_tally() public checkOwnerAndAccept {
        // See description above
//        require(is_tally_ready(), 108);
        m_is_tally_committed = true;
    }
    // ============================================

    // ============================================
    // Getters available to all participants
    // ============================================
    function get_crs_pk() public view returns (bytes) {
        tvm.accept();
        return m_crs.pk;
    }

    function get_crs_vk() public view returns (bytes) {
        tvm.accept();
        return m_crs.vk;
    }

    function get_voters_addresses() public view returns (address[]) {
        tvm.accept();
        address[] ret;
        for ((address addr,) : m_session_state.voter_map_accepted) {
            ret.push(addr);
        }
        return ret;
    }

    function get_pk_eid() public view returns (bytes) {
        tvm.accept();
        return m_session_state.pk_eid;
    }

    function get_vk_eid() public view returns (bytes) {
        tvm.accept();
        return m_session_state.vk_eid;
    }

    function get_eid() public view returns (bytes) {
        tvm.accept();
        return m_eid;
    }

    function get_rt() public view returns (bytes) {
        tvm.accept();
        return m_session_state.rt;
    }

    function get_ct_sum() public view returns (bytes) {
        tvm.accept();
        require(m_is_tally_committed, 110);
        return m_session_state.ct_sum;
    }

    function get_m_sum() public view returns (bytes) {
        tvm.accept();
        require(m_is_tally_committed, 110);
        return m_session_state.m_sum;
    }

    function get_dec_proof() public view returns (bytes) {
        tvm.accept();
        require(m_is_tally_committed, 110);
        return m_session_state.dec_proof;
    }
    // ============================================

    function get_voter_status(address voter_addr) public view checkOwnerAndAccept returns (bool) {
        require(m_session_state.voter_map_accepted.exists(voter_addr), 108);
        return m_session_state.voter_map_accepted.at(voter_addr);
    }

    function get_voters_statuses() public view checkOwnerAndAccept returns (mapping(address => bool)) {
        return m_session_state.voter_map_accepted;
    }

    function reset_voter_msg_accepted() public checkOwnerAndAccept {
        m_voter_msg_accepted = 0;
    }

    function get_voter_msg_accepted() public view checkOwnerAndAccept returns (uint32) {
        return m_voter_msg_accepted;
    }

    function get_is_tally_committed() public view checkOwnerAndAccept returns (bool) {
        return m_is_tally_committed;
    }

    bytes public m_eid;
    SharedStructs.CRS public m_crs;
    SharedStructs.SessionState public m_session_state;
    mapping(bytes => optional(bool))  m_all_eid;
    mapping(bytes => optional(bool))  m_all_sn;
    uint32 m_voter_msg_accepted;
    bool m_is_tally_committed;
}
