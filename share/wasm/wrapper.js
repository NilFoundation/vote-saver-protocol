const cli = require("./cli.js")

/**
 * 
 * @param {Uint8Array} blob 
 * @returns {number}
 */
function Uint8ArrayToBufferPtr(blob) {
    ptr = cli._malloc(blob.length);
    size = blob.length;
    cli.HEAPU8.subarray(ptr, ptr+size).set(blob);
    
    buff_ptr = cli._malloc(8);
    buff_ptri32 = buff_ptr >> 2;
    cli.HEAPU32.subarray(buff_ptri32, buff_ptri32+2).set([size, ptr]);
    return buff_ptr;
}

/**
 * 
 * @param {Uint8Array[]} blobs
 * @returns {number}
 */
function Uint8ArrayArrayToSuperBufferPtr(blobs) {
    buffers = blobs.map(blob => Uint8ArrayToBufferPtr(blob));
    size_in_bytes = blobs.length * 4;
    ptr = cli._malloc(size_in_bytes);
    size = blobs.length;
    ptr_i32 = ptr >> 2;
    cli.HEAPU32.subarray(ptr_i32, ptr_i32+size).set(buffers);
    
    super_buff_ptr = cli._malloc(8);
    super_buff_ptri32 = buff_ptr >> 2;
    cli.HEAPU32.subarray(buff_ptri32, buff_ptri32+2).set([size, ptr]);
    return buff_ptr;
}

/**
 * 
 * @param {number} buff_ptr 
 * @returns {Uint8Array}
 */
function BufferPtrToUint8ArrayAndFree(buff_ptr) {
    buff_ptri32 = buff_ptr >> 2;
    let [size, ptr] = cli.HEAPU32.subarray(buff_ptri32, buff_ptri32+2);
    array  = new Uint8Array(cli.HEAPU8.subarray(ptr,ptr+size));
    cli._free(ptr);
    return array
}

/**
 * 
 * @param {number} buff_ptr 
 */
function freeBuffer(buff_ptr) {
    buff_ptri32 = buff_ptr >> 2;
    let [size, ptr] = cli.HEAPU32.subarray(buff_ptri32, buff_ptri32+2);
    cli._free(ptr);
}

/**
 * 
 * @param {number} super_buff_ptr 
 */
function freeSuperBuffer(super_buff_ptr) {
    super_buff_ptri32 = super_buff_ptr >> 2;
    let [size, ptr] = cli.HEAPU32.subarray(super_buff_ptri32, super_buff_ptri32+2);
    
    ptr_i32 = ptr >> 2;
    buffers_view = cli.HEAPU32.subarray(ptr_i32, ptr_i32+size);
    for(let i = 0; i < size; ++i) {
        freeBuffer(buffers_view[i]);
    }
    cli._free(ptr);
}



/**
 * @typedef {Object} VoterKeypair
 * @property {Uint8Array} public_key - The X Coordinate
 * @property {Uint8Array} secret_key - The Y Coordinate
 */

/**
 * 
 * @returns {VoterKeypair}
 */
exports.generate_voter_keypair = function() {
    public_key_bptr = cli._malloc(8);
    secret_key_bptr = cli._malloc(8);
    cli._generate_voter_keypair(public_key_bptr, secret_key_bptr);
    public_key_blob = BufferPtrToUint8ArrayAndFree(public_key_bptr);
    secret_key_blob = BufferPtrToUint8ArrayAndFree(secret_key_bptr);
    cli._free(public_key_bptr);
    cli._free(secret_key_bptr);
    return {
        public_key: public_key_blob,
        secret_key: secret_key_blob
    };
}

/**
 * 
 * @typedef {Object} ElectionConfig
 * @property {Uint8Array} r1cs_proving_key
 * @property {Uint8Array} r1cs_verification_key
 * @property {Uint8Array} public_key
 * @property {Uint8Array} secret_key
 * @property {Uint8Array} verification_key
 * @property {Uint8Array} eid
 * @property {Uint8Array} rt
 */

const eid_len = 64;

/**
 * @param {number} tree_depth
 * @param {number} eid_bits
 * @param {Uint8Array[]} public_keys
 * 
 * @returns {ElectionConfig}
 */
exports.init_election = function (tree_depth, public_keys) {
    public_keys_super_buffer = Uint8ArrayArrayToSuperBufferPtr(public_keys);
    
    r1cs_proving_key_bptr = cli._malloc(8);
    r1cs_verification_key_bptr = cli._malloc(8);
    public_key_bptr = cli._malloc(8);
    secret_key_bptr = cli._malloc(8);
    verification_key_bptr = cli._malloc(8);
    eid_bptr = cli._malloc(8);
    rt_bptr = cli._malloc(8);

    cli._init_election(tree_depth, eid_len, public_keys_super_buffer,
                       r1cs_proving_key_bptr, r1cs_verification_key_bptr,
                       public_key_bptr, secret_key_bptr, verification_key_bptr,
                       eid_bptr, rt_bptr);
    
    r1cs_proving_key_blob = BufferPtrToUint8ArrayAndFree(r1cs_proving_key_bptr);
    r1cs_verification_key_blob = BufferPtrToUint8ArrayAndFree(r1cs_verification_key_bptr);
    public_key_blob = BufferPtrToUint8ArrayAndFree(public_key_bptr);
    secret_key_blob = BufferPtrToUint8ArrayAndFree(secret_key_bptr);
    verification_key_blob = BufferPtrToUint8ArrayAndFree(verification_key_bptr);
    eid_blob = BufferPtrToUint8ArrayAndFree(eid_bptr);
    rt_blob = BufferPtrToUint8ArrayAndFree(rt_bptr);
    
    freeSuperBuffer(public_keys_super_buffer);
    cli._free(public_keys_super_buffer);
    cli._free(r1cs_proving_key_bptr);
    cli._free(r1cs_verification_key_bptr);
    cli._free(public_key_bptr);
    cli._free(secret_key_bptr);
    cli._free(verification_key_bptr);
    cli._free(eid_bptr);
    cli._free(rt_bptr);
    
    return {
        r1cs_proving_key: r1cs_proving_key_blob,
        r1cs_verification_key: r1cs_verification_key_blob,
        public_key: public_key_blob,
        secret_key: secret_key_blob,
        verification_key: verification_key_blob,
        eid: eid_blob,
        rt: rt_blob
    };
}

/**
 * @typedef {Object} VoteData
 * @property {Uint8Array} proof
 * @property {Uint8Array} pinput
 * @property {Uint8Array} ct
 * @property {Uint8Array} sn
 */

/**
 * 
 * @param {number} tree_depth 
 * @param {number} voter_index 
 * @param {number} vote 
 * @param {Uint8Array[]} public_keys 
 * @param {Uint8Array} rt 
 * @param {Uint8Array} eid 
 * @param {Uint8Array} sk 
 * @param {Uint8Array} pk_eid 
 * @param {Uint8Array} r1cs_proving_key 
 * @param {Uint8Array} r1cs_verification_key 
 * @returns {VoteData}
 */
exports.generate_vote = function (tree_depth, voter_index, vote, public_keys,
              rt, eid, sk, pk_eid, r1cs_proving_key,
              r1cs_verification_key) {
    public_keys_super_buffer = Uint8ArrayArrayToSuperBufferPtr(public_keys);
    rt_buffer = Uint8ArrayToBufferPtr(rt);
    eid_buffer = Uint8ArrayToBufferPtr(eid);
    sk_buffer = Uint8ArrayToBufferPtr(sk);
    pk_eid_buffer = Uint8ArrayToBufferPtr(pk_eid);
    r1cs_proving_key_buffer = Uint8ArrayToBufferPtr(r1cs_proving_key);
    r1cs_verification_key_buffer = Uint8ArrayToBufferPtr(r1cs_verification_key);
    

    proof_buffer_out = cli._malloc(8);
    pinput_buffer_out = cli._malloc(8);
    ct_buffer_out = cli._malloc(8);
    sn_buffer_out = cli._malloc(8);

    cli._generate_vote(tree_depth, voter_index, vote, public_keys_super_buffer,
        rt_buffer, eid_buffer, sk_buffer, pk_eid_buffer,
        r1cs_proving_key_buffer, r1cs_verification_key_buffer,
        proof_buffer_out, pinput_buffer_out, ct_buffer_out,
        sn_buffer_out);
    
    proof_blob = BufferPtrToUint8ArrayAndFree(proof_buffer_out);
    pinput_blob = BufferPtrToUint8ArrayAndFree(pinput_buffer_out);
    ct_blob = BufferPtrToUint8ArrayAndFree(ct_buffer_out);
    sn_blob = BufferPtrToUint8ArrayAndFree(sn_buffer_out);

    cli._free(proof_buffer_out);
    cli._free(pinput_buffer_out);
    cli._free(ct_buffer_out);
    cli._free(sn_buffer_out);

    freeSuperBuffer(public_keys_super_buffer);
    cli._free(public_keys_super_buffer);
    freeBuffer(rt_buffer);
    cli._free(rt_buffer);
    freeBuffer(eid_buffer);
    cli._free(eid_buffer);
    freeBuffer(sk_buffer);
    cli._free(sk_buffer);
    freeBuffer(pk_eid_buffer);
    cli._free(pk_eid_buffer);
    freeBuffer(r1cs_proving_key_buffer);
    cli._free(r1cs_proving_key_buffer);
    freeBuffer(r1cs_verification_key_buffer);
    cli._free(r1cs_verification_key_buffer);

    return {
        proof: proof_blob,
        pinput: pinput_blob,
        ct: ct_blob,
        sn: sn_blob
    }
}

