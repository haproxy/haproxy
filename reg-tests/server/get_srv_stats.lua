local function lua_get_srv_stats(txn, name)
	for _, backend in pairs(core.backends) do
		for _, server in pairs(backend.servers) do
			if server.name == name then
				return server:get_stats()
			end
		end
	end
end

core.register_fetches('get_srv_stats', lua_get_srv_stats)
