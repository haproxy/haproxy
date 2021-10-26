
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

	local body = ""

	for i = 0, 200 do
	   body = body .. i .. ' ABCDEFGHIJKLMNOPQRSTUVWXYZ\n'
        end

	local httpclient = core.httpclient()
	local response = httpclient:post{url="http://127.0.0.1:" .. vtc_port, body=body}

	core.Info("Received: " .. response.body)
end

core.register_task(cron)
