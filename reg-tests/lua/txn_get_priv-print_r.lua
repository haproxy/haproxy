-- Copyright 2016 Thierry Fournier

function color(index, str)
	return "\x1b[" .. index .. "m" .. str .. "\x1b[00m"
end

function nocolor(index, str)
	return str
end

function sp(count)
	local spaces = ""
	while count > 0 do
		spaces = spaces .. "    "
		count = count - 1
	end
	return spaces
end

function escape(str)
	local s = ""
	for i = 1, #str do
		local c = str:sub(i,i)
		local ascii = string.byte(c, 1)
		if ascii > 126 or ascii < 20 then
			s = s .. string.format("\\x%02x", ascii)
		else
			s = s .. c
		end
	end
	return s
end

function print_rr(p, indent, c, wr, hist)
	local i = 0
	local nl = ""

	if type(p) == "table" then
		wr(c("33", "(table)") .. " " .. c("36", tostring(p)) .. " [")

		for idx, value in ipairs(hist) do
			if value == p then
				wr(" " .. c("35", "/* recursion */") .. " ]")
				return
			end
		end
		hist[indent + 1] = p

		mt = getmetatable(p)
		if mt ~= nil then
			wr("\n" .. sp(indent+1) .. c("31", "METATABLE") .. ": ")
			print_rr(mt, indent+1, c, wr, hist)
		end

		for k,v in pairs(p) do
			if i > 0 then
				nl = "\n"
			else
				wr("\n")
			end
			wr(nl .. sp(indent+1))
			if type(k) == "number" then
				wr(c("32", tostring(k)))
			else
				wr("\"" .. c("32", escape(tostring(k))) .. "\"")
			end
			wr(": ")
			print_rr(v, indent+1, c, wr, hist)
			i = i + 1
		end
		if i == 0 then
			wr(" " .. c("35", "/* empty */") .. " ]")
		else
			wr("\n" .. sp(indent) .. "]")
		end

		hist[indent + 1] = nil

	elseif type(p) == "string" then
		wr(c("33", "(string)") .. " \"" .. c("36", escape(p)) .. "\"")
	else
		wr(c("33", "(" .. type(p) .. ")") .. " " .. c("36", tostring(p)))
	end
end

function print_r(p, col, wr)
	if col == nil then col = true end
	if wr == nil then wr = function(msg) io.stdout:write(msg) end end
	local hist = {}
	if col == true then
		print_rr(p, 0, color, wr, hist)
	else
		print_rr(p, 0, nocolor, wr, hist)
	end
	wr("\n")
end
