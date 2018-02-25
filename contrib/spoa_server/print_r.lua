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

function print_rr(p, indent, c, wr)
	local i = 0
	local nl = ""

	if type(p) == "table" then
		wr(c("33", "(table)") .. " " .. c("34", tostring(p)) .. " [")

		mt = getmetatable(p)
		if mt ~= nil then
			wr("\n" .. sp(indent+1) .. c("31", "METATABLE") .. ": ")
			print_rr(mt, indent+1, c, wr)
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
				wr("\"" .. c("32", tostring(k)) .. "\"")
			end
			wr(": ")
			print_rr(v, indent+1, c, wr)
			i = i + 1
		end
		if i == 0 then
			wr(" " .. c("35", "/* empty */") .. " ]")
		else
			wr("\n" .. sp(indent) .. "]")
		end
	elseif type(p) == "string" then
		wr(c("33", "(string)") .. " \"" .. c("34", p) .. "\"")
	else
		wr(c("33", "(" .. type(p) .. ")") .. " " .. c("34", tostring(p)))
	end
end

function print_r(p, col, wr)
	if col == nil then col = true end
	if wr == nil then wr = function(msg) io.stdout:write(msg) end end
	if col == true then
		print_rr(p, 0, color, wr)
	else
		print_rr(p, 0, nocolor, wr)
	end
	wr("\n")
end
