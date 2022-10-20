function test()
	local httpclient = core.httpclient()
	local response = httpclient:get{url="http://127.0.0.1", headers={ [ "Host" ] = { "localhost" } }}

end


core.register_action("test", {"tcp-req"}, test, 0)
