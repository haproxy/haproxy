
local vtc_port1 = 0
local mailsreceived = 0
local mailconnectionsmade = 0
local healthcheckcounter = 0

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

	if RecieveAndCheck(applet, "HELO") == false then
	   applet:set_var("txn.result", "ERROR (step: HELO)")
	   return
	end
	applet:send("250 OK\r\n")
	if RecieveAndCheck(applet, "MAIL FROM:") == false then
	   applet:set_var("txn.result", "ERROR (step: MAIL FROM)")
	   return
	end
	applet:send("250 OK\r\n")
	if RecieveAndCheck(applet, "RCPT TO:") == false then
	   applet:set_var("txn.result", "ERROR (step: RCPT TO)")
	   return
	end
	applet:send("250 OK\r\n")
	if RecieveAndCheck(applet, "DATA") == false then
	   applet:set_var("txn.result", "ERROR (step: DATA)")
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
	core.Info("#### Body received OK")
	applet:send("250 OK\r\n")

	if RecieveAndCheck(applet, "QUIT") == false then
	   applet:set_var("txn.result", "ERROR (step: QUIT)")
	   return
	end
	applet:send("221 Mail queued for delivery to /dev/null \r\n")
	core.Info("Mail queued for delivery to /dev/null subject: "..subject)
	applet:set_var("txn.result", "SUCCESS")
end)
