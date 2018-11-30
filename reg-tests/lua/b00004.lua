
local vtc_port = 0

core.register_service("fakeserv", "http", function(applet)
	vtc_port = applet.headers["vtcport"][0]
	core.Info("APPLET START")
	local response = "OK"
	applet:add_header("Server", "haproxy/webstats")
	applet:add_header("Content-Length", string.len(response))
	applet:add_header("Content-Type", "text/html")
	applet:start_response()
	applet:send(response)
	core.Info("APPLET DONE")
end)

local function cron()
	-- wait for until the correct port is set through the c0 request..
	while vtc_port == 0 do
		core.msleep(1)
	end
	core.Debug('CRON port:' .. vtc_port)

	local socket = core.tcp()
	local success = socket:connect("127.0.0.1", vtc_port)
	core.Info("SOCKET MADE ".. (success or "??"))
	if success ~= 1 then
		core.Info("CONNECT SOCKET FAILED?")
		return
	end
	local request = "GET / HTTP/1.1\r\n\r\n"
	core.Info("SENDING REQUEST")
	socket:send(request)
	local result = ""
	repeat
		core.Info("4")
		local d = socket:receive("*a")
		if d ~= nil then
			result = result .. d
		end
	until d == nil or d == 0
	core.Info("Received: "..result)
end

core.register_task(cron)