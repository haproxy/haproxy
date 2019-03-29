core.register_service("foo.http", "http", function(applet)
    core.msleep(10)
    applet:start_response()
end)

core.register_service("foo.tcp", "tcp", function(applet)
   applet:send("HTTP/1.1 200 OK\r\nTransfer-encoding: chunked\r\n\r\n0\r\n\r\n")
end)
