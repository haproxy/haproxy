-- http-response actions
core.register_action("set-status-418-defaultreason", {"http-res"}, function(txn)
	txn.http:res_set_status(418)
end)
core.register_action("set-status-418-customreason", {"http-res"}, function(txn)
	txn.http:res_set_status(418, "I'm a coffeepot")
end)

-- http services
core.register_service("http418-default", "http", function(applet)
   local response = "Hello World !"
   applet:set_status(418)
   applet:add_header("content-length", string.len(response))
   applet:add_header("content-type", "text/plain")
   applet:start_response()
   applet:send(response)
end)

core.register_service("http418-coffeepot", "http", function(applet)
   local response = "Hello World !"
   applet:set_status(418, "I'm a coffeepot")
   applet:add_header("content-length", string.len(response))
   applet:add_header("content-type", "text/plain")
   applet:start_response()
   applet:send(response)
end)
