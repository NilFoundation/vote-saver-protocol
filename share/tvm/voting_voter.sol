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

    function vote(bytes eid, bytes sn, bytes proof, bytes ct, bytes proof_rerand, bytes ct_rerand) public checkOwnerAndAccept {
        require(!SharedStructs.cmp_bytes(ct, ct_rerand), 205);
        require(!SharedStructs.cmp_bytes(proof, proof_rerand), 206);

        // TODO: vergrth16
        bytes verification_input;
        verification_input.append(proof);
        verification_input.append(m_crs_vk);
        verification_input.append(m_pk_eid);
        verification_input.append(ct);
        verification_input.append(eid);
        verification_input.append(sn);
        verification_input.append(m_rt);
        // require(tvm.vergrth16(verification_input), 207);

        SharedStructs.Ballot ballot;
        ballot.eid = eid;
        ballot.sn = sn;
        ballot.proof = proof_rerand;
        ballot.ct = ct_rerand;
        m_ballot = ballot;

        m_is_vote_accepted = false;
        IAdmin(m_current_admin).check_ballot{callback: on_check_ballot}(eid, sn);
    }

    function get_ct() external checkAdminAndAccept responsible override returns (optional(bytes)) {
        if (!m_ballot.hasValue()) {
            return null;
        }
        return m_ballot.get().ct;
    }

    function on_get_session_data(bytes crs_vk, bytes pk_eid, bytes rt) public checkAdminAndAccept {
        m_crs_vk = crs_vk;
        m_pk_eid = pk_eid;
        m_rt = rt;
    }

    function on_check_ballot(bool result) public checkAdminAndAccept {
        m_is_vote_accepted = result;
    }

    address m_current_admin;
    bytes public m_crs_vk;
    bytes public m_pk_eid;
    bytes public m_rt;
    bytes public m_pk;
    bool public m_is_vote_accepted;
    optional(SharedStructs.Ballot) public m_ballot;
}
