
local vtc_port = 0
local vtc_port2 = 0
local vtc_port3 = 0

core.register_service("fakeserv", "http", function(applet)
	vtc_port = applet.headers["vtcport"][0]
	vtc_port2 = applet.headers["vtcport2"][0]
	vtc_port3 = applet.headers["vtcport3"][0]
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
	local httpclient = core.httpclient()

	-- wait for until the correct port is set through the c0 request..
	while vtc_port == 0 do
		core.msleep(1)
	end
	core.Debug('CRON port:' .. vtc_port)

	local body = ""

	for i = 0, 2000 do
	   body = body .. i .. ' ABCDEFGHIJKLMNOPQRSTUVWXYZ\n'
        end
	core.Info("First httpclient request")
	local response = httpclient:post{url="http://127.0.0.1:" .. vtc_port, body=body}
	core.Info("Received: " .. response.body)

	body = response.body

	core.Info("Second httpclient request")
	local response2 = httpclient:post{url="http://127.0.0.1:" .. vtc_port2, body=body}

	core.Info("Third httpclient request")
	local response3 = httpclient:get{url="http://127.0.0.1", dst = vtc_port3, headers={ [ "Host" ] = { "foobar.haproxy.local" } }}

end

core.register_task(cron)
