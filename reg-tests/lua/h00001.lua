core.register_action("bug", { "http-res" }, function(txn)
	data = txn:get_priv()
	if not data then
		data = 0
	end
	data = data + 1
	print(string.format("set to %d", data))
	txn.http:res_set_status(200 + data)
	txn:set_priv(data)
end)

core.register_service("fakeserv", "http", function(applet)
	applet:set_status(200)
	applet:start_response()
end)
