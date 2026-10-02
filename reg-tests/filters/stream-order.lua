-- Attach ordinals expose the global instance order; headers expose each
-- channel order. Counters are scoped to a configured proxy, not shared streams.
local counters = {}

local function register(name, htx, decline)
    local F = {
        id = "stream-order-" .. name,
        flags = htx and filter.FLT_CFG_FL_HTX or 0,
        tag = name,
    }

    function F:new()
        if decline then
            return nil
        end
        counters[self.scope] = (counters[self.scope] or 0) + 1
        return setmetatable({
            ordinal = counters[self.scope],
            started = {},
        }, { __index = self })
    end

    function F:start_analyze(txn, chn)
        self.started[chn:is_resp() and 2 or 1] = true
        return filter.CONTINUE
    end

    function F:http_headers(txn, msg)
        if not self.started[msg.channel:is_resp() and 2 or 1] then
            msg:set_header("x-filter-start", "missing")
        end
        local previous = msg:get_headers()["x-filter-order"]
        local order = previous and previous[0] or ""
        msg:set_header("x-filter-order", order .. self.scope .. self.tag .. ":" .. self.ordinal .. ";")
        return filter.CONTINUE
    end

    core.register_filter(name, F, function(conf, args)
        conf.scope = args[1]
        return conf
    end)
end

register("a", true, false)
register("b", true, false)
register("c", true, false)
register("disabled", true, false)
register("skip", true, true)
register("tcp-only", false, false)
