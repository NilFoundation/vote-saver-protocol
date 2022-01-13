import tonos_ts4.ts4 as ts4
import random
import string
import os

eq = ts4.eq

ts4.init('tvm/', verbose = True)

admin_keypair = ts4.make_keypair()
admin_instance = ts4.BaseContract('voting_admin', ctor_params = {'pk': 'abcd', 'vk': '1234'}, keypair = admin_keypair)
assert eq(admin_keypair, admin_instance.keypair)
ts4.register_nickname(admin_instance.address, 'Admin')

voters_number = 4
voters_keypairs = [ts4.make_keypair() for _ in range(voters_number)]
voters_pks = [ts4.Bytes(''.join(random.choices(string.hexdigits, k=16))) for _ in range(voters_number)]
voters_instances = [ts4.BaseContract('voting_voter', ctor_params = {'pk': pk, 'admin': admin_instance.address}, keypair = keypair) for pk, keypair in zip(voters_pks, voters_keypairs)]
voters_ballots = [{'sn': ts4.Bytes(''.join(random.choices(string.hexdigits, k=16))), 'proof': ts4.Bytes(''.join(random.choices(string.hexdigits, k=16))), 'ct': ts4.Bytes(''.join(random.choices(string.hexdigits, k=16))), 'proof_rerand': ts4.Bytes(''.join(random.choices(string.hexdigits, k=16))), 'ct_rerand': ts4.Bytes(''.join(random.choices(string.hexdigits, k=16)))} for _ in range(voters_number)]
for i, inst in zip(range(voters_number), voters_instances):
    ts4.register_nickname(inst.address, f'Voter{i}')

eid = '123456'
rt = '2345'
elgamal_pk = '7890'
elgamal_vk = '5634'
chosen_voters_addresses = [inst.address for inst in voters_instances[:]]
admin_instance.call_method_signed('init_voting_session', {'eid': eid, 'pk_eid': elgamal_pk, 'vk_eid': elgamal_vk, 'voters_addresses': chosen_voters_addresses, 'rt': rt})
ts4.dispatch_messages()

for inst, ballot in zip(voters_instances, voters_ballots):
    inst.call_method_signed('update_ballot', {'eid': eid, 'sn': ballot['sn'], 'proof': ballot['proof'], 'ct': ballot['ct'], 'proof_rerand': ballot['proof_rerand'], 'ct_rerand': ballot['ct_rerand']})
    msg_ping = ts4.peek_msg()
    assert eq(inst.address, msg_ping.src)
    assert eq(admin_instance.address, msg_ping.dst)
    ts4.dispatch_messages()
    inst.call_method_signed('commit_ballot', {})
    ts4.dispatch_messages()
    answer = inst.call_getter('m_is_vote_accepted')
    assert eq(True, answer)
    admin_instance.call_method_signed('get_voter_ct', {'voter_addr': inst.address})
    ts4.dispatch_messages()
    answer = admin_instance.call_getter('m_recieved_ct')
    assert str(ballot['ct_rerand']).lower() == str(answer).lower()

voters_instances[0].call_method_signed('update_ballot', {'eid': eid, 'sn': voters_ballots[0]['sn'], 'proof': voters_ballots[0]['proof'], 'ct': voters_ballots[0]['ct'], 'proof_rerand': voters_ballots[0]['proof_rerand'], 'ct_rerand': voters_ballots[0]['ct_rerand']})
ts4.dispatch_messages()
answer = voters_instances[0].call_getter('m_is_vote_accepted')
assert eq(False, answer)

admin_instance.call_method_signed('get_voter_ct', {'voter_addr': voters_instances[0].address}, expect_ec = 108)
ts4.dispatch_messages()
answer = admin_instance.call_getter('m_recieved_ct')
print(answer)

