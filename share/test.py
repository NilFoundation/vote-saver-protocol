import tonos_ts4.ts4 as ts4

eq = ts4.eq

ts4.init('tvm/', verbose = False)

keypair_admin = ts4.make_keypair()
admin = ts4.BaseContract('voting_admin', ctor_params = {'pk': 'abcd', 'vk': '1234'}, keypair = keypair_admin)
assert eq(keypair_admin, admin.keypair)

keypair_session = ts4.make_keypair()
session = ts4.BaseContract('voting_session', ctor_params = {'admin': admin.address}, keypair = keypair_session)

admin.call_method_signed('init_voting_session', {'session_addr': session.address, 'pk_eid': '1234', 'vk_eid': '2345', 'pklist': [], 'eid': '3456', 'rt': '4567'})
