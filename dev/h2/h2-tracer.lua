-- This is an HTTP/2 tracer for a TCP proxy. It will decode the frames that are
-- exchanged between the client and the server and indicate their direction,
-- types, flags and lengths. Lines are prefixed with a connection number modulo
-- 4096 that allows to sort out multiplexed exchanges. In order to use this,
-- simply load this file in the global section and use it from a TCP proxy:
--
--   global
--       lua-load "dev/h2/h2-tracer.lua"
--
--   listen h2_sniffer
--       mode tcp
--       bind :8002
--       filter lua.h2-tracer #hex
--       server s1 127.0.0.1:8003
--

-- define the decoder's class here
Dec = {}
Dec.id = "Lua H2 tracer"
Dec.flags = 0
Dec.__index = Dec
Dec.args = {}  -- args passed by the filter's declaration
Dec.cid = 0    -- next connection ID

-- prefix to indent responses
res_pfx = "                                         | "

-- H2 frame types
h2ft = {
    [0] = "DATA",
    [1] = "HEADERS",
    [2] = "PRIORITY",
    [3] = "RST_STREAM",
    [4] = "SETTINGS",
    [5] = "PUSH_PROMISE",
    [6] = "PING",
    [7] = "GOAWAY",
    [8] = "WINDOW_UPDATE",
    [9] = "CONTINUATION",
}

h2ff = {
    [0] = { [0] = "ES", [3] = "PADDED" }, -- data
    [1] = { [0] = "ES", [2] = "EH", [3] = "PADDED", [5] = "PRIORITY" }, -- headers
    [2] = { }, -- priority
    [3] = { }, -- rst_stream
    [4] = { [0] = "ACK" }, -- settings
    [5] = { [2] = "EH", [3] = "PADDED" }, -- push_promise
    [6] = { [0] = "ACK" }, -- ping
    [7] = { }, -- goaway
    [8] = { }, -- window_update
    [9] = { [2] = "EH" }, -- continuation
}

function Dec:new()
    local dec = {}

    setmetatable(dec, Dec)
    dec.do_hex = false
    if (Dec.args[1] == "hex") then
        dec.do_hex = true
    end

    Dec.cid = Dec.cid+1
    -- mix the thread number when multithreading.
    dec.cid = Dec.cid + 64 * core.thread

    -- state per dir. [1]=req [2]=res
    dec.st = {
        [1] = {
            hdr = { 0, 0, 0, 0, 0, 0, 0, 0, 0 },
            fofs = 0,
            flen = 0,
            ftyp = 0,
            fflg = 0,
            sid = 0,
            tot = 0,
        },
        [2] = {
            hdr = { 0, 0, 0, 0, 0, 0, 0, 0, 0 },
            fofs = 0,
            flen = 0,
            ftyp = 0,
            fflg = 0,
            sid = 0,
            tot = 0,
        },
    }
    return dec
end

function Dec:start_analyze(txn, chn)
    if chn:is_resp() then
        io.write(string.format("[%03x] ", self.cid % 4096) .. res_pfx .. "### res start\n")
    else
        io.write(string.format("[%03x] ", self.cid % 4096) .. "### req start\n")
    end
    filter.register_data_filter(self, chn)
end

function Dec:end_analyze(txn, chn)
    if chn:is_resp() then
        io.write(string.format("[%03x] ", self.cid % 4096) .. res_pfx .. "### res end: " .. self.st[2].tot .. " bytes total\n")
    else
        io.write(string.format("[%03x] ", self.cid % 4096) .. "### req end: " ..self.st[1].tot.. " bytes total\n")
    end
end

function Dec:tcp_payload(txn, chn)
    local data = { }
    local dofs = 1
    local pfx = ""
    local dir = 1
    local sofs = 0
    local ft = ""
    local ff = ""

    if chn:is_resp() then
        pfx = res_pfx
        dir = 2
    end

    pfx = string.format("[%03x] ", self.cid % 4096) .. pfx

    -- stream offset before processing
    sofs = self.st[dir].tot

    if (chn:input() > 0) then
        data = chn:data()
        self.st[dir].tot = self.st[dir].tot + chn:input()
    end

    if (chn:input() > 0 and self.do_hex ~= false) then
        io.write("\n" .. pfx .. "Hex:\n")
        for i = 1, #data do
            if ((i & 7) == 1) then io.write(pfx) end
            io.write(string.format("0x%02x ", data:sub(i, i):byte()))
            if ((i & 7) == 0 or i == #data) then io.write("\n") end
        end
    end

    -- start at byte 1 in the <data> string
    dofs = 1

    -- the first 24 bytes are expected to be an H2 preface on the request
    if (dir == 1 and sofs < 24) then
        -- let's not check it for now
        local bytes = self.st[dir].tot - sofs
        if (sofs + self.st[dir].tot >= 24) then
            -- skip what was missing from the preface
            dofs = dofs + 24 - sofs
            sofs = 24
            io.write(pfx .. "[PREFACE len=24]\n")
        else
            -- consume more preface bytes
            sofs = sofs + self.st[dir].tot
            return
        end
    end

    -- parse contents as long as there are pending data

    while true do
        -- check if we need to consume data from the current frame
        -- flen is the number of bytes left before the frame's end.
        if (self.st[dir].flen > 0) then
            if dofs > #data then return end -- missing data
            if (#data - dofs + 1 < self.st[dir].flen) then
                -- insufficient data
                self.st[dir].flen = self.st[dir].flen - (#data - dofs + 1)
                io.write(pfx .. string.format("%32s\n", "... -" .. (#data - dofs + 1) .. " = " .. self.st[dir].flen))
                dofs = #data + 1
                return
            else
                -- enough data to finish
                if (dofs == 1) then
                    -- only print a partial size if the frame was interrupted
                    io.write(pfx .. string.format("%32s\n", "... -" .. self.st[dir].flen .. " = 0"))
                end
                dofs = dofs + self.st[dir].flen
                self.st[dir].flen = 0
            end
        end

        -- here, flen = 0, we're at the beginning of a new frame --

        -- read possibly missing header bytes until dec.fofs == 9
        while self.st[dir].fofs < 9 do
            if dofs > #data then return end -- missing data
            self.st[dir].hdr[self.st[dir].fofs + 1] = data:sub(dofs, dofs):byte()
            dofs = dofs + 1
            self.st[dir].fofs = self.st[dir].fofs + 1
        end

        -- we have a full frame header here
        if (self.do_hex ~= false) then
            io.write("\n" .. pfx .. string.format("hdr=%02x %02x %02x %02x %02x %02x %02x %02x %02x\n",
                     self.st[dir].hdr[1], self.st[dir].hdr[2], self.st[dir].hdr[3],
                     self.st[dir].hdr[4], self.st[dir].hdr[5], self.st[dir].hdr[6],
                     self.st[dir].hdr[7], self.st[dir].hdr[8], self.st[dir].hdr[9]))
        end

        -- we have a full frame header, we'll be ready
        -- for a new frame once the data is gone
        self.st[dir].flen = self.st[dir].hdr[1] * 65536 +
                            self.st[dir].hdr[2] * 256 +
                            self.st[dir].hdr[3]
        self.st[dir].ftyp = self.st[dir].hdr[4]
        self.st[dir].fflg = self.st[dir].hdr[5]
        self.st[dir].sid  = self.st[dir].hdr[6] * 16777216 +
                            self.st[dir].hdr[7] * 65536 +
                            self.st[dir].hdr[8] * 256 +
                            self.st[dir].hdr[9]
        self.st[dir].fofs = 0

        -- decode frame type
        if self.st[dir].ftyp <= 9 then
            ft = h2ft[self.st[dir].ftyp]
        else
            ft = string.format("TYPE_0x%02x\n", self.st[dir].ftyp)
        end

        -- decode frame flags for frame type <ftyp>
        ff = ""
        for i = 7, 0, -1 do
            if (((self.st[dir].fflg >> i) & 1) ~= 0) then
                if self.st[dir].ftyp <= 9 and h2ff[self.st[dir].ftyp][i] ~= nil then
                    ff = ff .. ((ff == "") and "" or "+")
                    ff = ff .. h2ff[self.st[dir].ftyp][i]
                else
                    ff = ff .. ((ff == "") and "" or "+")
                    ff = ff .. string.format("0x%02x", 1<<i)
                end
            end
        end

        io.write(pfx .. string.format("[%s %ssid=%u len=%u (bytes=%u)]\n",
            ft, (ff == "") and "" or ff .. " ",
            self.st[dir].sid, self.st[dir].flen,
            (#data - dofs + 1)))
    end
end

core.register_filter("h2-tracer", Dec, function(dec, args)
    Dec.args = args
    return dec
end)
