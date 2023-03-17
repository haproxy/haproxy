-- haproxy event-handling from Lua
--
-- This file serves as a demo to show you the various events that
-- can be handled directly from custom lua functions.
-- Events captured from lua will be printed directly to STDOUT
-- It may not be exhaustive, please refer to the lua documentation
-- in doc/lua-api/index.rst for up-to-date content and further explanations

-- subscribe to every SERVER family events, this is the equivalent of doing:
-- core.event_sub({"SERVER_ADD", "SERVER_DEL", "SERVER_UP", "SERVER_DOWN"}, ...)
core.event_sub({"SERVER"}, function(event, data)
	-- This function will be called when:
	--  - new server is added from the CLI (SERVER_ADD)
	--  - existing server is removed from the CLI (SERVER_DEL)
	--  - existing server state changes from UP to DOWN (SERVER_DOWN)
	--  - existing server state changes from DOWN to UP (SERVER_UP)
	-- If the server still exists at the time the function is called, data["reference"]
	-- contains a valid reference to the lua server object related to the event
	--
        sv_status = data["reference"] ~= nil and data["reference"]:get_stats().status or "DELETED"
        print("[DEBUG - FROM LUA]", "EventType." .. event .. ": " ..
              "server " .. data["proxy_name"] .. "/" .. data["name"] .. " " ..
              "is " .. sv_status)
end)
-- Please note that you may also use Server.event_sub() method to subscribe to events
-- relative to a specific server only. See the lua documentation for more information.

-- New event families will be added over time...
