#import <Foundation/Foundation.h>

void devote_generate_keypair(NSMutableData *const pk_out, NSMutableData *const sk_out);

void devote_generate_vote(size_t tree_depth, size_t voter_idx, size_t vote, const NSData *const merkle_tree,
                          const NSData *const rt, const NSData *const eid, const NSData *const sk,
                          const NSData *const pk_eid, const NSData *const proving_key,
                          const NSData *const verification_key, NSMutableData *const proof_out,
                          NSMutableData *const pinput_out, NSMutableData *const ct_out, NSMutableData *const sn_out);

bool devote_verify_tally(size_t tree_depth,
                         const NSArray<NSData *> *const cts,
                         const NSData *const vk_eid,
                         const NSData *const pk_crs,
                         const NSData *const vk_crs,
                         const NSData *const voting_res,
                         const NSData *const dec_proof);
