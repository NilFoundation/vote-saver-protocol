
#import "ios.h"
#import "ios.hpp"

@implementation DeVote
+ (void) generate_voter_keypair
{
    std::vector<std::uint8_t> pk;
    std::vector<std::uint8_t> sk;
    process_encrypted_input_mode_init_voter_phase(0, pk, sk);
}
@end // DeVote
