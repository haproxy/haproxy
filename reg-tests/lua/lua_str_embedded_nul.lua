-- Lua strings may contain a \0 byte, a sample string may not.

core.register_fetches("plain_str", function(txn)
    return "public"
end)

core.register_fetches("nul_str", function(txn)
    return "public\0x"
end)

core.register_converters("nul_conv", function(str)
    return str .. "\0x"
end)

core.register_action("nul_var", { "http-req" }, function(txn)
    txn:set_var("txn.lua", "public\0x")
end)
