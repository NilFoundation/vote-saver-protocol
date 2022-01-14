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

    function update_admin(address new_admin) public checkOwnerAndAccept {
        m_current_admin = new_admin;
    }

    function reset_ballot() public checkOwnerAndAccept {
        m_ballot.vi = hex"";
        m_ballot.ct_begin = 0;
        m_ballot.eid_begin = 0;
        m_ballot.sn_begin = 0;
        m_ballot.sn_end = 0;

        IAdmin(m_current_admin).uncommit_ballot{callback: on_uncommit_ballot}();
    }

    function update_ballot(bytes vi) public checkOwnerAndAccept {
        m_ballot.vi.append(vi);

        IAdmin(m_current_admin).uncommit_ballot{callback: on_uncommit_ballot}();
    }

    function commit_ballot(uint32 ct_begin, uint32 eid_begin, uint32 sn_begin, uint32 sn_end) public checkOwnerAndAccept {
        require(m_ballot.vi.length > sn_end, 207);
        require(sn_end > sn_begin, 208);
        require(sn_begin > eid_begin, 209);
        require(eid_begin > ct_begin, 210);

        m_ballot.ct_begin = ct_begin;
        m_ballot.eid_begin = eid_begin;
        m_ballot.sn_begin = sn_begin;
        m_ballot.sn_end = sn_end;

        require(tvm.vergrth16(m_ballot.vi), 211);

        IAdmin(m_current_admin).check_ballot{callback: on_check_ballot, value: 200000000}(m_ballot.vi[eid_begin:sn_begin], m_ballot.vi[sn_begin:sn_end]);
    }

    function get_vi_len() public view checkOwnerAndAccept returns (uint) {
        return m_ballot.vi.length;
    }

    function get_ct() public view returns (bytes) {
        tvm.accept();
        if (!m_is_vote_accepted) {
            return hex"";
        }
        return m_ballot.vi[m_ballot.ct_begin:m_ballot.eid_begin];
    }

    function is_vote_accepted() public view checkOwnerAndAccept returns (bool) {
        return m_is_vote_accepted;
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
    bytes public m_pk;
    bool public m_is_vote_accepted;
    SharedStructs.Ballot public m_ballot;
}
