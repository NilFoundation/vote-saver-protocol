pragma ton-solidity >= 0.30.0;

contract VerifyGroth16EncInput {
  bytes private m_input_blob;
  bool private ans;

  function get_gas_value(uint128 gas) public view returns (uint128 value) {
    require(msg.pubkey() == tvm.pubkey(), 150);

    return gasToValue(gas, 0);
  }

  function get_ans() public view returns (bool answer) {
    require(msg.pubkey() == tvm.pubkey(), 150);

    return ans;
  }

  function set_input(bytes tail) public {
    require(msg.pubkey() == tvm.pubkey(), 150);
    tvm.accept();

    ans = false;
    m_input_blob = tail;
  }

  function get_input() public view returns (bytes input) {
    require(msg.pubkey() == tvm.pubkey(), 150);
    tvm.accept();

    return m_input_blob;
  }

  function get_input_len() public view returns (uint input_len) {
    require(msg.pubkey() == tvm.pubkey(), 150);

    return m_input_blob.length;
  }

  function reset_input() public {
    require(msg.pubkey() == tvm.pubkey(), 150);
    
    ans = false;
    m_input_blob = hex"";
  }
  
  function verify() public {
    require(msg.pubkey() == tvm.pubkey(), 150);
    tvm.accept();

    ans = false;
    ans = tvm.vergrth16(m_input_blob);
  }

  modifier checkOwnerAndAccept {
    require(msg.pubkey() == tvm.pubkey(), 100);
    tvm.accept();
    _;
  }

  constructor() public checkOwnerAndAccept { }

  function sendTransaction(address dest, uint128 value, bool bounce) public pure checkOwnerAndAccept {
    dest.transfer(value, bounce, 3);
  }

  receive() external {
  }
}
