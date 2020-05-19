core.register_service("set_var", "http", function(applet)
	local var_name = applet.headers["var"][0]
	local result = applet:set_var(var_name, "value")
	if result then
		applet:set_status(202)
	else
		applet:set_status(400)
	end
	applet:add_header("echo", applet:get_var(var_name) or "(nil)")
	applet:start_response()
	applet:send("")
end)

core.register_service("set_var_ifexist", "http", function(applet)
	local var_name = applet.headers["var"][0]
	local result = applet:set_var(var_name, "value", true)
	if result then
		applet:set_status(202)
	else
		applet:set_status(400)
	end
	applet:add_header("echo", applet:get_var(var_name) or "(nil)")
	applet:start_response()
	applet:send("")
end)
