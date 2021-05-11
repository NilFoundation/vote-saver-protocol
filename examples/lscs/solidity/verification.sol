pragma ton -solidity >= 0.35.0;
pragma AbiHeader expire;

contract verification {
    constructor() public {
        // check that contract's public key is set
        require(tvm.pubkey() != 0, 101);
        // Check that message has signature (msg.pubkey() is not zero) and message is signed with the owner's private key
        require(msg.pubkey() == tvm.pubkey(), 102);
        tvm.accept();
    }

    // Function that adds its argument to the state variable.
    function verify(bytes value) public returns (bool) {
        TvmBuilder builder;
        builder.store(value);
        return tvm.vergrth16(builder.toCell());
    }
}