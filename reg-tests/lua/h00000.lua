core.register_action("foo", { "http-req" }, function(txn)
	txn.sc:ipmask(txn.f:src(), 24, 112)
end)
