
local vtc_port1 = 0
local mailsreceived = 0
local mailconnectionsmade = 0
local healthcheckcounter = 0

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

core.register_service("luahttpservice", "http", function(applet)
	local response = "?"
	local responsestatus = 200
       if applet.path == "/setport" then
		vtc_port1 = applet.headers["vtcport1"][0]
		response = "OK"
	end
	if applet.path == "/svr_healthcheck" then
		healthcheckcounter = healthcheckcounter + 1
		if healthcheckcounter < 2 or healthcheckcounter > 6 then
			responsestatus = 403
		end
	end

	applet:set_status(responsestatus)
       if applet.path == "/checkMailCounters" then
		response = "MailCounters"
		applet:add_header("mailsreceived", mailsreceived)
		applet:add_header("mailconnectionsmade", mailconnectionsmade)
	end
	applet:start_response()
	applet:send(response)
end)

core.register_service("fakeserv", "http", function(applet)
	applet:set_status(200)
	applet:start_response()
end)

function RecieveAndCheck(applet, expect)
	data = applet:getline()
	if data:sub(1,expect:len()) ~= expect then
		core.Info("Expected: "..expect.." but got:"..data:sub(1,expect:len()))
		applet:send("Expected: "..expect.." but got:"..data.."\r\n")
		return false
	end
	return true
end

core.register_service("mailservice", "tcp", function(applet)
	core.Info("############# Mailservice Called #############")
	mailconnectionsmade = mailconnectionsmade + 1
	applet:send("220 Welcome\r\n")
	local data

	if RecieveAndCheck(applet, "EHLO") == false then
		return
	end
	applet:send("250 OK\r\n")
	if RecieveAndCheck(applet, "MAIL FROM:") == false then
		return
	end
	applet:send("250 OK\r\n")
	if RecieveAndCheck(applet, "RCPT TO:") == false then
		return
	end
	applet:send("250 OK\r\n")
	if RecieveAndCheck(applet, "DATA") == false then
		return
	end
	applet:send("354 OK\r\n")
	core.Info("#### Send your mailbody")
	local endofmail = false
	local subject = ""
	while endofmail ~= true do
		data = applet:getline() -- BODY CONTENT
		--core.Info(data)
		if data:sub(1, 9) == "Subject: " then
			subject = data
		end
		if (data == "\r\n") then
			data = applet:getline() -- BODY CONTENT
			core.Info(data)
			if (data == ".\r\n") then
				endofmail = true
			end
		end
	end
	core.Info("#### Body recieved OK")
	applet:send("250 OK\r\n")

	if RecieveAndCheck(applet, "QUIT") == false then
		return
	end
	applet:send("221 Mail queued for delivery to /dev/null \r\n")
	core.Info("Mail queued for delivery to /dev/null subject: "..subject)
	mailsreceived = mailsreceived + 1
end)
