pragma ton-solidity >= 0.30.0;

import "voting_interface.sol";

contract SaverVoter is IVoter {
    constructor(bytes pk, address admin) public {
        require(tvm.pubkey() != 0, 201);
        require(msg.pubkey() == tvm.pubkey(), 202);
        tvm.accept();

        m_pk = pk;
        m_current_admin = admin;
    }

    modifier checkOwnerAndAccept {
        require(msg.pubkey() == tvm.pubkey(), 203);
        tvm.accept();
        _;
    }

    modifier checkAdminAndAccept {
        require(msg.pubkey() != 0, 204);
        require(msg.sender == m_current_admin, 205);
        tvm.accept();
        _;
    }

    function get_pk() public view returns (bytes) {
        return m_pk;
    }

    function update_admin(address new_admin) public checkOwnerAndAccept {
        m_current_admin = new_admin;
    }

    function vote(bytes eid, bytes sn, bytes proof, bytes ct) public view checkOwnerAndAccept {
        tvm.accept();
        SharedStructs.Ballot ballot;
        ballot.sn = sn;
        ballot.proof = proof;
        ballot.ct = ct;
        IAdmin(m_current_admin).send_ballot(eid, ballot);
    }

    // @return (status, sn, proof, ct)
    function get_my_vote(bytes eid) public view checkOwnerAndAccept returns (bool, bytes, bytes, bytes) {
        return IAdmin(m_current_admin).get_vote(eid).await;
    }

    address m_current_admin;
    bytes public m_pk;
}
