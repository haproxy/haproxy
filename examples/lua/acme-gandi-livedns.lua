-- ACME dns-01 automation via event_hdl callbacks using the Gandi LiveDNS API v5
--
-- HAProxy Configuration:
--
-- global
--     expose-experimental-directives
--     tune.lua.bool-sample-conversion normal
--     lua-load examples/lua/acme-gandi-livedns.lua
--     log stderr local0
--
-- acme LE
--     directory https://acme-staging-v02.api.letsencrypt.org/directory
--     contact foobar@example.com
--     challenge dns-01
--     challenge-ready cli,dns
--
-- crt-store
--     load crt foobar.pem acme LE domains *.foobar.example.com
--
-- Start HAProxy with the GANDI_API_KEY variable:
--
-- GANDI_API_KEY=fer89wf498w4f98we74f98wwiw787f8we4f8 ./haproxy -W -f haproxy.cfg
--
-- Gandi Personal Access Token (https://account.gandi.net -> Security -> Personal Access Tokens).
-- Set the GANDI_API_KEY environment variable before starting HAProxy.
local GANDI_API_KEY = os.getenv("GANDI_API_KEY") or error("GANDI_API_KEY environment variable is not set")

-- Gandi LiveDNS API base URL.
local GANDI_API_URL = "https://api.gandi.net/v5/livedns"

-- ---------------------------------------------------------------------------
-- Gandi LiveDNS helpers
-- ---------------------------------------------------------------------------

-- Try to set the _acme-challenge TXT records for <domain> to <txt_values>.
-- Probes each possible parent zone (longest first) until Gandi accepts one.
-- Returns the zone and record name on success, or nil on failure.
local function dns_set_txt(domain, txt_values)
    local labels = {}
    for label in domain:gmatch("[^.]+") do
        labels[#labels + 1] = label
    end

    for i = 1, #labels - 1 do
        local zone = table.concat(labels, ".", i + 1)
        local name = "_acme-challenge." .. table.concat(labels, ".", 1, i)
        local url  = string.format("%s/domains/%s/records/%s/TXT", GANDI_API_URL, zone, name)
        local body = string.format('{"rrset_values":["%s"],"rrset_ttl":300}', table.concat(txt_values, '","'))

        core.log(core.debug, string.format("acme: trying PUT %s", url))

        local hc  = core.httpclient()
        local res = hc:put({
            url     = url,
            headers = {
                ["Authorization"] = { "Bearer " .. GANDI_API_KEY },
                ["Content-Type"]  = { "application/json" },
            },
            body = body,
        })

        if res and (res.status == 200 or res.status == 201) then
            core.log(core.notice, string.format(
                "acme: TXT record set: %s in zone %s", name, zone))
            return zone, name
        end
    end

    core.log(core.alert, string.format(
        "acme: failed to set TXT record for _acme-challenge.%s: no valid zone found", domain))
    return nil, nil
end

-- Deletes the TXT record identified by <zone> and <name>.
local function dns_del_txt(zone, name)
    local url = string.format("%s/domains/%s/records/%s/TXT", GANDI_API_URL, zone, name)

    core.log(core.notice, string.format("acme: DELETE %s", url))

    local hc  = core.httpclient()
    local res = hc:delete({
        url     = url,
        headers = {
            ["Authorization"] = { "Bearer " .. GANDI_API_KEY },
        },
    })

    if not res or res.status ~= 204 then
        local status = res and res.status or "nil"
        core.log(core.alert, string.format(
            "acme: Gandi DELETE failed for %s/%s (status=%s)", zone, name, status))
        return false
    end

    core.log(core.notice, string.format(
        "acme: TXT record deleted: %s in zone %s", name, zone))
    return true
end

-- ---------------------------------------------------------------------------
-- Tasks
-- ---------------------------------------------------------------------------

-- Track deployed TXT records per cert path so they can be cleaned up.
-- deployed[crt][domain] = { values = {...}, lock = queue, zone = ..., name = ... }
local deployed = {}

-- Spawn a background task per ACME_DEPLOY event to set the TXT record and
-- signal challenge readiness.  Using register_task keeps HTTP calls in a
-- plain task context.
core.event_sub({"ACME_DEPLOY"}, function(event, data, sub, when)
    local crt    = data.crtname
    local domain = data.domain
    local record = data.dns_record
    local identifier = data.wildcard and ("*." .. domain) or domain
    if not deployed[crt] then deployed[crt] = {} end
    local rec = deployed[crt][domain]
    if not rec then
        rec = { values = {}, lock = core.queue() }
        rec.lock:push(true)
        deployed[crt][domain] = rec
    end
    rec.values[#rec.values + 1] = record

    core.register_task(function()
        rec.lock:pop_wait()
        local ok, zone, name = pcall(dns_set_txt, domain, rec.values)
        rec.lock:push(true)
        if not ok or not zone then
            core.log(core.alert, string.format(
                "acme: aborting challenge for crt=%s domain=%s: %s", crt, identifier, tostring(zone)))
            return
        end

        -- Remember this record for cleanup on ACME_NEWCERT.
        rec.zone, rec.name = zone, name

        -- Signal HAProxy that the dns-01 challenge for this domain is ready.
        local ok, ret = pcall(ACME.challenge_ready, crt, identifier)
        if not ok then
            core.log(core.alert, string.format(
                "acme: challenge_ready error for crt=%s domain=%s: %s", crt, identifier, ret))
        elseif ret == 0 then
            core.log(core.notice, string.format(
                "acme: all challenges ready for crt=%s, validation starting", crt))
        else
            core.log(core.info, string.format(
                "acme: crt=%s domain=%s ready, %d challenge(s) still pending",
                crt, identifier, ret))
        end
    end)
end)

-- ACME_NEWCERT: remove the TXT records that were set for this certificate.
core.event_sub({"ACME_NEWCERT"}, function(event, data, sub, when)
    local crt = data.crtname
    if not deployed[crt] then return end

    core.register_task(function()
        for _, rec in pairs(deployed[crt]) do
            if rec.zone then dns_del_txt(rec.zone, rec.name) end
        end
        deployed[crt] = nil
    end)
end)
