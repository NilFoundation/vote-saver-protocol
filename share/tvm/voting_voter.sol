pragma ton-solidity >= 0.30.0;

import "voting_interface.sol";

contract SaverVoter is IVoter {
    constructor(bytes pk, address current_admin) public {
        require(tvm.pubkey() != 0, 101);
        require(msg.pubkey() == tvm.pubkey(), 102);
        tvm.accept();

        m_pk = pk;
        m_current_admin = current_admin;
    }

    modifier checkOwnerAndAccept {
        require(msg.pubkey() == tvm.pubkey(), 103);
        tvm.accept();
        _;
    }

    modifier checkAdminAndAccept {
        require(msg.pubkey() != 0, 104);
        require(msg.sender == m_current_admin, 105);
        tvm.accept();
        _;
    }

    function get_pk() public view returns (bytes) {
        return m_pk;
    }

    function update_admin(address new_admin) public checkOwnerAndAccept {
        m_current_admin = new_admin;
    }

    function vote(bytes eid, bytes sn, bytes proof, bytes ct) public view checkOwnerAndAccept returns (bool) {
        SharedStructs.Ballot ballot;
        ballot.sn = sn;
        ballot.proof = proof;
        ballot.ct = ct;
        return IAdmin(m_current_admin).send_ballot(eid, ballot).await;
    }

    // @return (status, sn, proof, ct)
    function get_my_vote(bytes eid) public view checkOwnerAndAccept returns (bool, bytes, bytes, bytes) {
        return IAdmin(m_current_admin).get_vote(eid).await;
    }

    address m_current_admin;
    bytes public m_pk;
}
