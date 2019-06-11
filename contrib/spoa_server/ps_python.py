from pprint import pprint
import spoa
import ipaddress
import random

def check_client_ip(args):
	pprint(args)
	spoa.set_var_null("null", spoa.scope_txn)
	spoa.set_var_boolean("boolean", spoa.scope_txn, True)
	spoa.set_var_int32("int32", spoa.scope_txn, 1234)
	spoa.set_var_uint32("uint32", spoa.scope_txn, 1234)
	spoa.set_var_int64("int64", spoa.scope_txn, 1234)
	spoa.set_var_uint64("uint64", spoa.scope_txn, 1234)
	spoa.set_var_ipv4("ipv4", spoa.scope_txn, ipaddress.IPv4Address(u"127.0.0.1"))
	spoa.set_var_ipv6("ipv6", spoa.scope_txn, ipaddress.IPv6Address(u"1::f"))
	spoa.set_var_str("str", spoa.scope_txn, "1::f")
	spoa.set_var_bin("bin", spoa.scope_txn, "1:\x01:\x02f\x00\x00")
	spoa.set_var_int32("ip_score", spoa.scope_sess, random.randint(1,100))
	return


spoa.register_message("check-client-ip", check_client_ip)
