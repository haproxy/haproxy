FilterA = {}
FilterA.id = "A filter"
FilterA.flags = filter.FLT_CFG_FL_HTX
FilterA.__index =  FilterA

function FilterA:new()
	local filter = {}
	setmetatable(filter, FilterA)
	return filter
end

function FilterA:start_analyze(txn, chn)
	if chn:is_resp() then
		core.Info("FilterA.resp")
	else
		core.Info("FilterA.req")
	end
end

core.register_filter("FilterA", FilterA, function(flt, args)
	return flt
end)

FilterB = {}
FilterB.id = "A filter"
FilterB.flags = filter.FLT_CFG_FL_HTX
FilterB.__index =  FilterB

function FilterB:new()
	local filter = {}
	setmetatable(filter, FilterB)
	return filter
end

function FilterB:start_analyze(txn, chn)
	if chn:is_resp() then
		core.Info("FilterB.resp")
	else
		core.Info("FilterB.req")
	end

end

core.register_filter("FilterB", FilterB, function(flt,args)
	return flt
end)
