pragma ton-solidity >= 0.30.0;

import "voting_interface.sol";

contract SaverVoter is IVoter {
    constructor(bytes pk, address admin) public {
        require(tvm.pubkey() != 0, 201);
        require(msg.pubkey() == tvm.pubkey(), 202);
        tvm.accept();

        m_pk = pk;
        m_current_admin = admin;
        m_is_vote_accepted = false;
        reset_callback_status();
    }

    modifier checkOwnerAndAccept {
        require(msg.pubkey() == tvm.pubkey(), 203);
        tvm.accept();
        _;
    }

    modifier checkAdminAndAccept {
        require(msg.sender == m_current_admin, 204);
        tvm.accept();
        _;
    }

    // ============================================
    // Voter could switch between different admins holding different sessions
    // ============================================
    function update_admin(address new_admin) public checkOwnerAndAccept {
        m_current_admin = new_admin;
        m_is_vote_accepted = false;
    }
    // ============================================

    // ============================================
    // Potential problem: if the system has the possibility of re-voting: after administrator finishes tally phase
    // (upload decrypted voting results and decryption proof) malicious voter could update its ballot to correct one but
    // different. Then according to protocol when voters begin to download encrypted ballots (call get_ct) of other
    // voters, due to replaced ballot from the malicious voter decryption verification will be failed and voting results
    // will be declined, so protocol execution violated.
    // Permissibility of such possibility depends on requirements specification for the application of the voting
    // system in production (in some cases re-voting may be needed).
    // Possible solution:
    // ============================================
//    function could_commit() private view returns (bool) {
//        return !m_is_vote_accepted;
//    }
    // ============================================

    // ============================================
    // Loading of the voters' ballot
    // ============================================
    function reset_ballot() public checkOwnerAndAccept {
        // See description above
//        require(could_commit(), 205);
        m_ballot.vi = hex"";
        m_ballot.proof_end = 0;
        m_ballot.ct_begin = 0;
        m_ballot.ct_begin = 0;
        m_ballot.eid_begin = 0;
        m_ballot.sn_begin = 0;
        m_ballot.rt_begin = 0;

        reset_callback_status();
        IAdmin(m_current_admin).uncommit_ballot{callback: on_uncommit_ballot}();
    }

    function update_ballot(bytes vi) public checkOwnerAndAccept {
        // See description above
//        require(could_commit(), 205);
        m_ballot.vi.append(vi);

        reset_callback_status();
        IAdmin(m_current_admin).uncommit_ballot{callback: on_uncommit_ballot}();
    }
    // ============================================

    // ============================================
    // Committing of the voter's ballot which make it possible to consider its vote
    // ============================================
    function commit_ballot(uint32 proof_end, uint32 ct_begin, uint32 ct_end, uint32 eid_begin, uint32 sn_begin, uint32 rt_begin) public checkOwnerAndAccept {
        // See description above
//        require(could_commit(), 205);
        require(m_ballot.vi.length > rt_begin, 207);
        require(rt_begin > sn_begin, 208);
        require(sn_begin > eid_begin, 209);
        require(eid_begin > ct_end, 210);
        require(ct_end > ct_begin, 211);
        require(ct_begin > proof_end, 212);

        require(tvm.vergrth16(m_ballot.vi), 213);

        m_ballot.proof_end = proof_end;
        m_ballot.ct_begin = ct_begin;
        m_ballot.ct_end = ct_end;
        m_ballot.eid_begin = eid_begin;
        m_ballot.sn_begin = sn_begin;
        m_ballot.rt_begin = rt_begin;

        reset_callback_status();
        IAdmin(m_current_admin).check_ballot{callback: on_check_ballot, value: 200000000}(m_ballot.vi[eid_begin:sn_begin], m_ballot.vi[sn_begin:rt_begin]);
    }
    // ============================================

    // ============================================
    // Getters available to all participants
    // ============================================
    function get_pk() public view returns (bytes) {
        tvm.accept();
        return m_pk;
    }

    function get_proof() public view returns (bytes) {
        tvm.accept();
        return m_ballot.vi[1:m_ballot.proof_end];
    }

    function get_ct() public view returns (bytes) {
        tvm.accept();
        return m_ballot.vi[m_ballot.ct_begin:m_ballot.ct_end];
    }

    function get_eid() public view returns (bytes) {
        tvm.accept();
        return m_ballot.vi[m_ballot.eid_begin:m_ballot.sn_begin];
    }

    function get_sn() public view returns (bytes) {
        tvm.accept();
        return m_ballot.vi[m_ballot.sn_begin:m_ballot.rt_begin];
    }

    function get_rt() public view returns (bytes) {
        tvm.accept();
        return m_ballot.vi[m_ballot.rt_begin:];
    }
    // ============================================

    function get_vi_len() public view checkOwnerAndAccept returns (uint) {
        return m_ballot.vi.length;
    }

    function get_vi() public view checkOwnerAndAccept returns (bytes) {
        return m_ballot.vi;
    }

    function is_vote_accepted() public view checkOwnerAndAccept returns (bool) {
        return m_is_vote_accepted;
    }

    function on_uncommit_ballot(int32 result_status) public checkAdminAndAccept {
        if (0 == result_status) {
            m_is_vote_accepted = false;
        }
        m_callback_status = result_status;
    }

    function on_check_ballot(int32 result_status) public checkAdminAndAccept {
        if (0 == result_status) {
            m_is_vote_accepted = true;
        }
        else {
            m_is_vote_accepted = false;
        }
        m_callback_status = result_status;
    }

    function set_pk(bytes pk) public checkOwnerAndAccept {
        m_pk = pk;
    }

    function reset_callback_status() public checkOwnerAndAccept {
        m_callback_status = -1;
    }
    
    function get_callback_status() public view checkOwnerAndAccept returns (int32) {
        return m_callback_status;
    }

    address m_current_admin;
    bytes public m_pk;
    bool public m_is_vote_accepted;
    SharedStructs.Ballot public m_ballot;
    int32 m_callback_status;
}
