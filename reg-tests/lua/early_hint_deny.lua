core.register_action("deny", { "http-req" }, function(txn)
    return act.DENY
end)
