Luacurl = {}
Luacurl.__index = Luacurl
setmetatable(Luacurl, {
	__call = function (cls, ...)
		return cls.new(...)
	end,
})
function Luacurl.new(server, port, ssl)
	local self = setmetatable({}, Luacurl)
	self.sockconnected = false
	self.server = server
	self.port = port
	self.ssl = ssl
	self.cookies = {}
	return self
end

function Luacurl:get(method,url,headers,data)
	core.Info("MAKING SOCKET")
	if self.sockconnected == false then
	  self.sock = core.tcp()
	  if self.ssl then
		local r = self.sock:connect_ssl(self.server,self.port)
	  else
		local r = self.sock:connect(self.server,self.port)
	  end
	  self.sockconnected = true
	end
	core.Info("SOCKET MADE")
	local request = method.." "..url.." HTTP/1.1"
	if data ~= nil then
		request = request .. "\r\nContent-Length: "..string.len(data)
	end
	if headers ~= null then
		for h,v in pairs(headers) do
			request = request .. "\r\n"..h..": "..v
		end
	end
	cookstring = ""
	for cook,cookval in pairs(self.cookies) do
		cookstring = cookstring .. cook.."="..cookval.."; "
	end
	if string.len(cookstring) > 0 then
		request = request .. "\r\nCookie: "..cookstring
	end

	request = request .. "\r\n\r\n"
	if data and string.len(data) > 0 then
		request = request .. data
	end
--print(request)
	core.Info("SENDING REQUEST")
	self.sock:send(request)

--	core.Info("PROCESSING RESPONSE")
	return processhttpresponse(self.sock)
end

function processhttpresponse(socket)
	local res = {}
core.Info("1")
	res.status = socket:receive("*l")
core.Info("2")

	if res.status == nil then
		core.Info(" processhttpresponse RECEIVING status: NIL")
		return res
	end
	core.Info(" processhttpresponse RECEIVING status:"..res.status)
	res.headers = {}
	res.headerslist = {}
	repeat
core.Info("3")
		local header = socket:receive("*l")
		if header == nil then
			return "error"
		end
		local valuestart = header:find(":")
		if valuestart ~= nil then
			local head = header:sub(1,valuestart-1)
			local value = header:sub(valuestart+2)
			table.insert(res.headerslist, {head,value})
			res.headers[head] = value
		end
	until header == ""
	local bodydone = false
	if res.headers["Connection"] ~= nil and res.headers["Connection"] == "close" then
--		core.Info("luacurl processresponse with connection:close")
		res.body = ""
		repeat
core.Info("4")
			local d = socket:receive("*a")
			if d ~= nil then
				res.body = res.body .. d
			end
		until d == nil or d == 0
		bodydone = true
	end
	if bodydone == false and res.headers["Content-Length"] ~= nil then
		res.contentlength = tonumber(res.headers["Content-Length"])
		if res.contentlength == nil then
		  core.Warning("res.contentlength ~NIL = "..res.headers["Content-Length"])
		end
--		core.Info("luacur, contentlength="..res.contentlength)
		res.body = ""
		repeat
			local d = socket:receive(res.contentlength)
			if d == nil then
--				core.Info("luacurl, ERROR?: received NIL, expecting "..res.contentlength.." bytes only got "..string.len(res.body).." sofar")
				return
			else
				res.body = res.body..d
--				core.Info("luacurl, COMPLETE?: expecting "..res.contentlength.." bytes, got "..string.len(res.body))
				if string.len(res.body) >= res.contentlength then
--					core.Info("luacurl, COMPLETE?: expecting "..res.contentlength.." bytes, got "..string.len(res.body))
					break
				end
			end
--			core.Info("processhttpresponse, Loopy, get more body data! to receive complete contentlenght")
		until false
	end
	if res.headers["Transfer-Encoding"] ~= nil and res.headers["Transfer-Encoding"] == "chunked" then
		local chunksize = 0
		res.contentlength = 0
		res.body = ""
		repeat
core.Info("5")
			local chunksizestr = socket:receive("*l")
			if chunksizestr == nil then
				break
			end
			chunksize = tonumber("0x"..chunksizestr)
			if chunksize ~= nil then
				res.contentlength = res.contentlength + chunksize
				if chunksize ~= 0 then
					local chunk = socket:receive(chunksize)
					res.body = res.body .. chunk
					chunksizestr = socket:receive("*l")
					if chunksizestr ~= "" then
						return "ERROR Chunk-end expected."
					end
				end
			else
				break
			end
		until false
	end
core.Info("6")
	return res
end

function Luacurl:close()
	if self.sockconnected == true then
		self.sock:close()
		self.sockconnected = false
	end
end

function print_r_string(object)
	local res = ""
	print_r(object,false,function(x) res = res .. x end)
	return res
end

core.register_service("fakeserv", "http", function(applet)
	core.Info("APPLET START")
	local mc = Luacurl("127.0.0.1",8443, true)
	local headers = {}
	local body = ""
	core.Info("APPLET GET")
	local res = mc:get("GET", "/", headers, body)
	core.Info("APPLET GET done")
	local response = print_r_string(res)
	applet:add_header("Server", "haproxy/webstats")
	applet:add_header("Content-Length", string.len(response))
	applet:add_header("Content-Type", "text/html")
	applet:start_response()
	applet:send(response)
	core.Info("APPLET DONE")
end)
