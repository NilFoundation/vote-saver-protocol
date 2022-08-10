#import <Foundation/Foundation.h>
#import "ios.hpp"

 namespace boost {
     void assertion_failed(char const *expr, char const *function, char const *file, long line) {
     }
     void assertion_failed_msg(char const *expr, char const *msg, char const *function, char const *file, long line) {
     }
 }    // namespace boost

 std::vector<std::uint8_t> readNSData_to_vector(const NSData * const data) {
     uint8_t* begin = (uint8_t*) data.bytes;
     uint8_t* end  = begin + data.length;
     return std::vector<std::uint8_t> (begin, end);
 }

 void write_vector_to_NSData(const std::vector<std::uint8_t> &vector,
                             NSMutableData * const data) {
     [data appendBytes:vector.data() length:vector.size()];
 }

extern "C" {
 void devote_generate_keypair(NSMutableData * const pk_out, NSMutableData * const sk_out) {
     std::vector<std::uint8_t> pk_out_vector;
     std::vector<std::uint8_t> sk_out_vector;
     process_encrypted_input_mode_init_voter_phase(0, pk_out_vector, sk_out_vector);
     write_vector_to_NSData(pk_out_vector, pk_out);
     write_vector_to_NSData(sk_out_vector, sk_out);
 }

 void devote_generate_vote(
     size_t tree_depth, size_t voter_idx, size_t vote,
     const NSData * const merkle_tree,
     const NSData * const rt,
     const NSData * const eid,
     const NSData * const sk,
     const NSData * const pk_eid,
     const NSData * const proving_key,
     const NSData * const verification_key,
     NSMutableData * const proof_out,
     NSMutableData * const pinput_out,
     NSMutableData * const ct_out,
     NSMutableData * const sn_out) {
    
     std::vector<std::uint8_t> merkle_tree_vector = readNSData_to_vector(merkle_tree);
     std::vector<std::uint8_t> rt_vector = readNSData_to_vector(rt);
     std::vector<std::uint8_t> eid_vector = readNSData_to_vector(eid);
     std::vector<std::uint8_t> sk_vector = readNSData_to_vector(sk);
     std::vector<std::uint8_t> pk_eid_vector = readNSData_to_vector(pk_eid);
     std::vector<std::uint8_t> proving_key_vector = readNSData_to_vector(proving_key);
     std::vector<std::uint8_t> verification_key_vector = readNSData_to_vector(verification_key);

     std::vector<std::uint8_t> proof_out_vector;
     std::vector<std::uint8_t> pinput_out_vector;
     std::vector<std::uint8_t> ct_out_vector;
     std::vector<std::uint8_t> sn_out_vector;

     const std::size_t eid_bits = 64;

     process_encrypted_input_mode_vote_phase(tree_depth, eid_bits, voter_idx, vote, merkle_tree_vector, rt_vector,
                                             eid_vector, sk_vector, pk_eid_vector, proving_key_vector, verification_key_vector,
                                             proof_out_vector, pinput_out_vector, ct_out_vector, sn_out_vector);

     write_vector_to_NSData(proof_out_vector, proof_out);
     write_vector_to_NSData(pinput_out_vector, pinput_out);
     write_vector_to_NSData(ct_out_vector, ct_out);
     write_vector_to_NSData(sn_out_vector, sn_out);
 }

 bool devote_verify_tally(
     size_t tree_depth,
     const NSArray<NSData*> * const cts,
     const NSData * const vk_eid,
     const NSData * const pk_crs,
     const NSData * const vk_crs,
     const NSData * const voting_res,
     const NSData * const dec_proof) {
    
     std::vector<std::vector<std::uint8_t> > cts_vector;
     for(id data in cts) {
         cts_vector.push_back(readNSData_to_vector(data));
     }

     std::vector<std::uint8_t> vk_eid_vector = readNSData_to_vector(vk_eid);
     std::vector<std::uint8_t> pk_crs_vector = readNSData_to_vector(pk_crs);
     std::vector<std::uint8_t> vk_crs_vector = readNSData_to_vector(vk_crs);
     std::vector<std::uint8_t> voting_res_vector = readNSData_to_vector(voting_res);
     std::vector<std::uint8_t> dec_proof_vector = readNSData_to_vector(dec_proof);

     return process_encrypted_input_mode_tally_voter_phase(
     tree_depth,
     cts_vector,
     vk_eid_vector,
     pk_crs_vector,
     vk_crs_vector,
     voting_res_vector,
     dec_proof_vector);
 }
}