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
        require(msg.sender == m_current_admin, 204);
        tvm.accept();
        _;
    }

    function get_pk() public view returns (bytes) {
        return m_pk;
    }

    function update_admin(address new_admin) public checkOwnerAndAccept {
        m_current_admin = new_admin;
    }

    function vote(bytes eid, bytes sn, bytes proof, bytes ct, bytes proof_rerand, bytes ct_rerand) public checkOwnerAndAccept {
        require(!SharedStructs.cmp_bytes(ct, ct_rerand), 205);
        require(!SharedStructs.cmp_bytes(proof, proof_rerand), 206);
        tvm.accept();
        SharedStructs.Ballot ballot;
        ballot.sn = sn;
        ballot.proof = proof;
        ballot.ct = ct;
        SharedStructs.Ballot ballot_rerand;
        ballot_rerand.sn = sn;
        ballot_rerand.proof = proof_rerand;
        ballot_rerand.ct = ct_rerand;
        m_is_vote_accepted = 1;
        IAdmin(m_current_admin).send_ballot{callback: SaverVoter.on_vote}(eid, ballot, ballot_rerand);
    }

    function on_vote(uint8 status) public checkAdminAndAccept {
        m_is_vote_accepted = status;
    }

    function get_my_vote(bytes eid) public checkOwnerAndAccept {
        m_my_vote = null;
        IAdmin(m_current_admin).get_vote{callback: SaverVoter.on_get_my_vote}(eid);
    }

    function on_get_my_vote(optional(SharedStructs.Ballot) my_vote) public checkAdminAndAccept {
        m_my_vote = my_vote;
    }

    address m_current_admin;
    bytes public m_pk;
    uint8 public m_is_vote_accepted;
    optional(SharedStructs.Ballot) public m_my_vote;
}
