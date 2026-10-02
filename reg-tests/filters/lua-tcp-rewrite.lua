-- Same-length, non-commuting substitutions make channel order observable on
-- the wire. No packet boundaries or transport timing enter the assertions.
local function register(name, from, to)
    local F = { id = name, flags = 0, from = from, to = to }

    function F:new()
        return setmetatable({}, { __index = self })
    end

    function F:start_analyze(txn, chn)
        filter.register_data_filter(self, chn)
        return filter.CONTINUE
    end

    function F:tcp_payload(txn, chn)
        local count = chn:input()
        if count == 0 then
            return 0
        end
        local data = chn:data(0, count)
        local replaced = data:gsub(self.from, self.to)
        assert(chn:set(replaced, 0, count) == count)
        return count
    end

    core.register_filter(name, F, function(conf, args)
        return conf
    end)
end

register("rewrite-a", "a", "b")
register("rewrite-b", "b", "c")
register("rewrite-c", "c", "a")
