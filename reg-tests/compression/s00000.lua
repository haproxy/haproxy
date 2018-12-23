
local data = "abcdefghijklmnopqrstuvwxyz"
local responseblob = ""
for i = 1,10000 do
  responseblob = responseblob .. "\r\n" .. i .. data:sub(1, math.floor(i % 27))
end

http01applet = function(applet)
  local response = responseblob
  applet:set_status(200)
  applet:add_header("Content-Type", "application/javascript")
  applet:add_header("Content-Length", string.len(response)*10)
  applet:start_response()
  for i = 1,10 do
    applet:send(response)
  end
end

core.register_service("fileloader-http01", "http", http01applet)
