-- Reusable HTTP probes. Arguments: scope, tag, mode (headers/data/wait/decline),
-- optional maximum bytes forwarded per payload callback. Only new() mutates
-- the construction counters; all callback state belongs to the stream instance.
local counters = {}

local function append(msg, header, value)
    local values = msg:get_headers()[header]
    msg:set_header(header, (values and values[0] or "") .. value .. ";")
end

local function register(name)
    local F = {
        id = "lua-probe-" .. name,
        flags = filter.FLT_CFG_FL_HTX,
    }

    function F:new()
        if self.mode == "decline" then
            return nil
        end
        counters[self.scope] = (counters[self.scope] or 0) + 1
        return setmetatable({
            serial = counters[self.scope],
            started = {},
            headers_seen = {},
            start_waited = {},
            headers_waited = {},
            bytes = { 0, 0 },
        }, { __index = self })
    end

    function F:start_analyze(txn, chn)
        local side = chn:is_resp() and 2 or 1
        if self.mode == "wait" and not self.start_waited[side] then
            self.start_waited[side] = true
            filter.wake_time(1)
            return filter.WAIT
        end
        self.started[side] = true
        self.headers_seen[side] = false
        self.bytes[side] = 0
        if self.mode == "data" or self.limit > 0 then
            filter.register_data_filter(self, chn)
        end
        return filter.CONTINUE
    end

    function F:http_headers(txn, msg)
        local side = msg:is_resp() and 2 or 1
        if self.mode == "wait" and not self.headers_waited[side] then
            self.headers_waited[side] = true
            filter.wake_time(1)
            return filter.WAIT
        end
        local tag = self.scope .. "." .. self.tag
        if not self.started[side] then
            append(msg, "x-probe-errors", tag .. ":missing-start")
        end
        if self.headers_seen[side] then
            append(msg, "x-probe-errors", tag .. ":duplicate-headers")
        end
        self.headers_seen[side] = true
        append(msg, "x-probe-order", tag)
        append(msg, "x-probe-instances", tag .. ":" .. self.serial)
        local encoding = msg:get_headers()["content-encoding"]
        append(msg, "x-probe-encodings", tag .. ":" .. (encoding and encoding[0] or "identity"))
        if side == 2 and (self.mode == "data" or self.limit > 0) then
            append(msg, "x-probe-request-bytes", tag .. ":" .. self.bytes[1])
        end
        return filter.CONTINUE
    end

    function F:http_payload(txn, msg)
        local side = msg:is_resp() and 2 or 1
        local count = msg:input()
        if self.limit > 0 and count > self.limit then
            count = self.limit
        end
        self.bytes[side] = self.bytes[side] + #(msg:body(0, count) or "")
        return count
    end

    function F:http_end(txn, msg)
        return filter.CONTINUE
    end

    core.register_filter(name, F, function(conf, args)
        assert(args[1] and args[2], "probe scope and tag are required")
        conf.scope = args[1]
        conf.tag = args[2]
        conf.mode = args[3] or "headers"
        conf.limit = tonumber(args[4]) or 0
        assert(conf.limit >= 0, "probe payload limit must not be negative")
        return conf
    end)
end

register("probe-a")
register("probe-b")
register("probe-c")
register("probe-d")
