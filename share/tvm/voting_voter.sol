pragma ton-solidity >= 0.30.0;

import "voting_interface.sol";

contract SaverVoter is IVoter {
    constructor(bytes pk, address admin) public {
        require(tvm.pubkey() != 0, 201);
        require(msg.pubkey() == tvm.pubkey(), 202);
        tvm.accept();

        m_pk = pk;
        m_current_admin = admin;
        IAdmin(admin).get_session_data{callback: on_get_session_data}();
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

    function update_admin(address new_admin) public checkOwnerAndAccept {
        m_current_admin = new_admin;
        IAdmin(new_admin).get_session_data{callback: on_get_session_data}();
    }

    function reset_ballot() public checkOwnerAndAccept {
        m_ballot = null;

        IAdmin(m_current_admin).uncommit_ballot{callback: on_uncommit_ballot}();
    }

    function update_ballot(bytes eid, bytes sn, bytes proof_rerand, bytes ct_rerand) public checkOwnerAndAccept {
        if (!m_ballot.hasValue()) {
            m_ballot = SharedStructs.Ballot("", "", "", "");
        }
        m_ballot.get().eid.append(eid);
        m_ballot.get().sn.append(sn);
        m_ballot.get().proof.append(proof_rerand);
        m_ballot.get().ct.append(ct_rerand);

        IAdmin(m_current_admin).uncommit_ballot{callback: on_uncommit_ballot}();
    }

    // TODO
    function reset_session_date() public checkOwnerAndAccept {
        m_crs_vk = hex"";
        m_pk_eid = hex"";
        m_rt = hex"";
    }

    // TODO
    function update_session_data(bytes crs_vk, bytes pk_eid, bytes rt) public checkOwnerAndAccept {
        m_crs_vk.append(crs_vk);
        m_pk_eid.append(pk_eid);
        m_rt.append(rt);
    }

    function commit_ballot() public view checkOwnerAndAccept {
        require(m_ballot.hasValue(), 207);

        bytes verification_input = hex"01";
        verification_input.append(m_ballot.get().proof);
        verification_input.append(m_crs_vk);
        verification_input.append(m_pk_eid);
        verification_input.append(m_ballot.get().ct);
        verification_input.append(m_ballot.get().eid);
        verification_input.append(m_ballot.get().sn);
        verification_input.append(m_rt);
        require(tvm.vergrth16(verification_input), 208);

        IAdmin(m_current_admin).check_ballot{callback: on_check_ballot}(m_ballot.get().eid, m_ballot.get().sn);
    }

    function get_vi_len() public view checkOwnerAndAccept returns (uint) {
        return m_ballot.get().proof.length + m_crs_vk.length + m_pk_eid.length + m_ballot.get().ct.length + m_ballot.get().eid.length + m_ballot.get().sn.length + m_rt.length;
    }

    function get_ct() external checkAdminAndAccept responsible override returns (optional(bytes)) {
        if (!m_ballot.hasValue()) {
            return null;
        }
        if (!m_is_vote_accepted) {
            return null;
        }
        return m_ballot.get().ct;
    }

    function on_get_session_data(bytes crs_vk, bytes pk_eid, bytes rt) public checkAdminAndAccept {
        m_crs_vk = crs_vk;
        m_pk_eid = pk_eid;
        m_rt = rt;
    }

    function on_uncommit_ballot(bool status) public checkAdminAndAccept {
        if (status) {
            m_is_vote_accepted = false;
        }
    }

    function on_check_ballot(bool result) public checkAdminAndAccept {
        m_is_vote_accepted = result;
    }

    address m_current_admin;
    bytes public m_crs_vk; // TODO
    bytes public m_pk_eid; // TODO
    bytes public m_rt; // TODO
    bytes public m_pk;
    bool public m_is_vote_accepted;
    optional(SharedStructs.Ballot) public m_ballot;
}
