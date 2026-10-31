-- Generates deterministic response bodies that are hard to compress, for
-- the output_margin_*.vtc files.
--
-- Patterns:
--   random : random bytes, which the deflater cannot compress at all
--   high   : random bytes >= 144, which cost 9 bits each with the fixed tree
--   mixed  : alternating random and repetitive text blocks of random sizes
--   sparse : random bytes with a short repeated sequence every 20-60 bytes,
--            i.e. matches that barely pay for themselves
--   runN   : runs of N random bytes >= 144 separated by 4-byte matches
--            copied from 8 bytes before, which are barely worth a reference
--            and exercise the deflater's switching between stored and
--            huffman blocks
--   text   : repetitive HTML-like text
--
-- Chunkings:
--   whole  : the whole body in one call, with a content-length
--   buf    : 4000-byte calls, close to the h1 buffer size, with a
--            content-length
--   small  : 1 to 64 bytes per call, chunked
--   odd    : 1 to 20000 bytes per call, chunked

-- Each pattern is generated once, as long as the longest body using it, and
-- shorter bodies are prefixes of it, so that all requests for the same
-- pattern and length get the same body. Random bytes come from a small LCG,
-- inlined and turned into strings 256 bytes at a time, since it's run under
-- ASAN in CI.
local max_len = {}

local phrase = "<div class=\"item\"><a href=\"/page?id=1234\">Some link text</a></div>\n"

local bodies = {}

local function make_body(pattern)
	if bodies[pattern] then
		return bodies[pattern]
	end

	local x = 12345
	local t = {}
	local len = 0
	local tail = ""

	local function rnd()
		x = (x * 1103515245 + 12345) % 2147483648
		return (x >> 16) & 0xff
	end

	local function add(s)
		t[#t + 1] = s
		len = len + #s
		tail = (tail .. s):sub(-8)
	end

	-- adds <count> random bytes >= <min>
	local function add_random(count, min)
		local a = {}
		local span = 256 - min
		for i = 1, count do
			x = (x * 1103515245 + 12345) % 2147483648
			a[i] = min + ((x >> 16) & 0xff) % span
		end
		for i = 1, count, 256 do
			add(string.char(table.unpack(a, i, math.min(i + 255, count))))
		end
	end

	local function add_text(count)
		add(string.rep(phrase, count // #phrase + 1):sub(1, count))
	end

	while len < max_len[pattern] do
		if pattern == "random" then
			add_random(4096, 0)
		elseif pattern == "high" then
			add_random(4096, 144)
		elseif pattern == "mixed" then
			add_random(300 + rnd() * 7, 0)
			add_text(300 + rnd() * 7)
		elseif pattern:sub(1, 3) == "run" then
			add_random(tonumber(pattern:sub(4)) or 51, 144)
			add(tail:sub(1, 4))
		elseif pattern == "sparse" then
			add_random(20 + rnd() % 40, 0)
			add(("wxyz1234"):sub(1, 4 + rnd() % 5))
		else
			add_text(4096)
		end
	end
	bodies[pattern] = table.concat(t):sub(1, max_len[pattern])
	return bodies[pattern]
end

-- small LCG for the chunk sizes
local function prng(seed)
	local x = seed
	return function()
		x = (x * 1103515245 + 12345) % 2147483648
		return (x >> 16) & 0xff
	end
end

-- The cases are served in order, one per request, from the set named in the
-- query string (/?set=<name>), so that each vtest client only has to loop
-- over the same request. Each set is used by its own output_margin_*.vtc file
-- so that vtest runs them in parallel. The body length is advertised in x-len
-- for the client to check it once decompressed.
local sets = {}
local next_case = {}

local function add_case(set, p, c, n)
	sets[set] = sets[set] or {}
	next_case[set] = 0
	table.insert(sets[set], { p = p, c = c, n = n })
	max_len[p] = math.max(max_len[p] or 0, n)
end

-- all patterns with 4 kB buffers, one set per chunking
for _, c in ipairs({ "whole", "buf", "small", "odd" }) do
	for _, p in ipairs({ "random", "high", "mixed", "sparse", "run4", "run51", "run53", "run200", "run349", "text" }) do
		add_case(c, p, c, 10000)
	end
end

-- sizes that leave little room in the buffer once received at once: with
-- 16 kB buffers, a tiny maxrewrite and these headers, haproxy before the fixes
-- crashed on 16086 to 16118 bytes, and responses of 16144 bytes or more are
-- not compressed at all.
for _, p in ipairs({ "random", "run51" }) do
	for n = 16088, 16116, 4 do
		add_case("full-" .. p, p, "whole", n)
	end
end

core.register_service("gen", "http", function(applet)
	local qs = applet.qs or ""
	local set = qs:match("set=([%w-]+)") or "whole"
	local cases = sets[set]
	local case = cases[next_case[set] % #cases + 1]
	local body, rnd
	local pos = 1

	next_case[set] = next_case[set] + 1

	-- explicit case, for debugging: /?p=<pattern>&c=<chunking>&n=<length>
	if qs:match("p=") then
		case = { p = qs:match("p=(%w+)"), c = qs:match("c=(%w+)") or "whole",
		         n = tonumber(qs:match("n=(%d+)") or 10000) }
		max_len[case.p] = math.max(max_len[case.p] or 0, case.n)
		bodies[case.p] = nil
	end

	body = make_body(case.p):sub(1, case.n)
	rnd = prng(54321)

	applet:set_status(200)
	applet:add_header("Content-Type", "text/plain")
	applet:add_header("x-len", #body)
	if case.c == "whole" or case.c == "buf" then
		applet:add_header("Content-Length", #body)
	end
	applet:start_response()

	while pos <= #body do
		local size
		if case.c == "buf" then
			size = 4000
		elseif case.c == "small" then
			size = 1 + rnd() % 64
		elseif case.c == "odd" then
			size = 1 + (rnd() * 256 + rnd()) % 20000
		else
			size = #body
		end
		applet:send(body:sub(pos, pos + size - 1))
		pos = pos + size
	end
end)
