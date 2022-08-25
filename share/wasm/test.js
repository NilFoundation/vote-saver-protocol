const wrapper = require("./wrapper.js");

function test() {
    tree_depth = 3;
    eid = 1;
    num_participants = 5;
    keypairs = [];
    public_keys = [];
    for(var i =0; i < num_participants; ++i) {
        // Voter method:
        // Android: https://github.com/NoamDev/vote-saver-android/blob/71bb9ded347b66a959bf108de15b2d165bfd983b/app/src/main/java/com/devoteusa/devote/DeVote.kt#L10
        // iOS: https://github.com/NilFoundation/vote-saver-protocol/blob/66647b1cfd249e1c464364833fab96537b8bbfae/bin/cli/include/devote_ios.h#L2
        keypair = wrapper.generate_voter_keypair();
        keypairs.push(keypair);
        public_keys.push(keypair.public_key);
    }
    admin_keys = wrapper.admin_keygen(tree_depth)
    election = wrapper.init_election(tree_depth, public_keys);
    vote_datas = []
    for(var i=0; i < num_participants; ++i) {
        vote = (i*3) % 25;
        console.log(`voter ${i} votes ${vote}`);
        // Voter method:
        // Android: https://github.com/NoamDev/vote-saver-android/blob/71bb9ded347b66a959bf108de15b2d165bfd983b/app/src/main/java/com/devoteusa/devote/DeVote.kt#L17
        // iOS: https://github.com/NilFoundation/vote-saver-protocol/blob/66647b1cfd249e1c464364833fab96537b8bbfae/bin/cli/include/devote_ios.h#L4
        vote_data = wrapper.generate_vote(tree_depth, i, vote, election.merkle_tree,
            election.rt, election.eid, keypairs[i].secret_key,
            admin_keys.public_key, admin_keys.r1cs_proving_key, admin_keys.r1cs_verification_key);
        vote_datas.push(vote_data);
    }
    cts = vote_datas.map(vote_data=>vote_data.ct);
    tally_data = wrapper.tally_votes(tree_depth, admin_keys.secret_key,
        admin_keys.verification_key, admin_keys.r1cs_proving_key,
        admin_keys.r1cs_verification_key, cts);
    
    console.log(tally_data.voting_res);    

    // Voter/Observer method
    // Android: https://github.com/NoamDev/vote-saver-android/blob/71bb9ded347b66a959bf108de15b2d165bfd983b/app/src/main/java/com/devoteusa/devote/DeVote.kt#L36
    // iOS: https://github.com/NilFoundation/vote-saver-protocol/blob/66647b1cfd249e1c464364833fab96537b8bbfae/bin/cli/include/devote_ios.h#L18
    is_tally_valid = wrapper.verify_tally(tree_depth, cts, admin_keys.verification_key,
        admin_keys.r1cs_proving_key, admin_keys.r1cs_verification_key,
        tally_data.dec_proof, tally_data.voting_res);
    
    console.log('is_tally_valid: ', is_tally_valid);
}
setTimeout(test, 300);