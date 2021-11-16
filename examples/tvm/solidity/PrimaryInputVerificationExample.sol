pragma ton-solidity >=0.30.0;

contract PrimaryInputVerificationExample {
    bytes constant m_vkey = hex""; //change that
    uint8 constant PROOF_SIZE = 192;
    uint32 constant PI_SIZE = 2; //change that
    uint8 constant field_element_bytes = 32;

    // You should change/add/remove arguments according to your circuit.
    function verify(bytes proof,
                    uint32 some_number,
                    uint256 serialized_field_element) {
        require(proof.length == PROOF_SIZE);
        tvm.accept();
        string blob_str = proof;
        blob_str.append(serialize_primary_input(some_number,serialized_field_element));
        blob_str.append(m_vkey);
        require(tvm.vergrth16(blob_str));
        // do whatever now that you know the proof is valid with these primary inputs :)
        // Btw, primary inputs could also originate from fields of the smart contract of course.
    }

    // You should change/add/remove arguments according to your circuit.
    function serialize_primary_input(uint32 some_number, uint256 serialized_field_element) internal inline view returns(bytes) {
        string blob_str=(encode_little_endian(PI_SIZE,4));
        blob_str.append(encode_little_endian(uint256(some_number), field_element_bytes));
        blob_str.append(uint256_to_bytes(serialized_field_element));
        return blob_str;
    }

    function encode_little_endian(uint256 number, uint32 bytes_size) internal pure returns (bytes){
        TvmBuilder ref_builder;
        for(uint32 i=0; i<bytes_size; ++i) {
            ref_builder.store(byte(uint8(number & 0xFF)));
            number>>=8;
        }
        TvmBuilder builder;
        builder.storeRef(ref_builder.toCell());
        return builder.toSlice().decode(bytes);
    }

    function uint256_to_bytes(uint256 number) internal pure returns (bytes){
        TvmBuilder ref_builder;
        ref_builder.store(bytes32(number));
        TvmBuilder builder;
        builder.storeRef(ref_builder.toCell());
        return builder.toSlice().decode(bytes);
    }
}