--[[
    This script can be used to decipher SSL traffic coming through haproxy. It
    must first be loaded in the global section of haproxy configuration with
    TLS keys logging activated :

      tune.ssl.keylog on
      lua-load sslkeylogger.lua

    Then a http-request rule can be inserted for the desired frontend :
      http-request lua.sslkeylog <path_to_keylog_file>

    The generated keylog file can then be injected into wireshark to decipher a
    network capture.
]]

local function sslkeylog(txn, filename)
	local fields = {
		CLIENT_EARLY_TRAFFIC_SECRET     = function() return txn.f:ssl_fc_client_early_traffic_secret()     end,
		CLIENT_HANDSHAKE_TRAFFIC_SECRET = function() return txn.f:ssl_fc_client_handshake_traffic_secret() end,
		SERVER_HANDSHAKE_TRAFFIC_SECRET = function() return txn.f:ssl_fc_server_handshake_traffic_secret() end,
		CLIENT_TRAFFIC_SECRET_0         = function() return txn.f:ssl_fc_client_traffic_secret_0()         end,
		SERVER_TRAFFIC_SECRET_0         = function() return txn.f:ssl_fc_server_traffic_secret_0()         end,
		EXPORTER_SECRET                 = function() return txn.f:ssl_fc_exporter_secret()                 end,
		EARLY_EXPORTER_SECRET           = function() return txn.f:ssl_fc_early_exporter_secret()           end
	}

	local client_random = txn.c:hex(txn.f:ssl_fc_client_random())

	-- ensure that a key is written only once by using a session variable
	if not txn:get_var('sess.sslkeylogdone') then
		local file, err = io.open(filename, 'a')
		if file then
			for fieldname, fetch in pairs(fields) do
				if fetch() then
					file:write(string.format('%s %s %s\n', fieldname, client_random, fetch()))
				end
			end
			file:close()
		else
			core.Warning("Cannot open SSL log file: " .. err .. ".")
		end

		txn:set_var('sess.sslkeylogdone', true)
	end
end

core.register_action('sslkeylog', { 'http-req' }, sslkeylog, 1)
