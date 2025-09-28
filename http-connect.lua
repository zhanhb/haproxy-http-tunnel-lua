local encode_char_map = {
    ["\""] = "\\\"",
    ["\\"] = "\\\\",
    ["\b"] = "\\b",
    ["\f"] = "\\f",
    ["\n"] = "\\n",
    ["\r"] = "\\r",
    ["\t"] = "\\t",
}

local function stringify(o)
    local type = type(o)
    if type == 'function' or type == 'userdata' then
        return '"' .. type .. '"'
    elseif type == 'table' then
        local list = {}
        for k, v in pairs(o) do
            list[1 + #list] = '"' .. k .. '": ' .. stringify(v)
        end
        return '{' .. table.concat(list, ',') .. '}'
    elseif type == 'string' then
        return '"' .. o:gsub('[%z\1-\31\\"\127]', function(ch)
            return encode_char_map[ch] or ('\\u%04x'):format(ch:byte())
        end) .. '"'
    elseif type == 'nil' then
        return 'null'
    else
        return tostring(o)
    end
end

local function must_regex(regex, case_sensitive)
    local st, res = Regex.new(regex, case_sensitive)
    if st then return res end
    error(string.format("regex='%s', reason='%s'", regex, res), 2)
end

local function common_res(txn, ret, status, ...)
    local cat = core.concat()
    cat:add('HTTP/1.1 ')
    cat:add(status)
    cat:add('\r\nDate: ')
    cat:add(txn.sc:http_date(txn.f:date()))
    local n = select('#', ...)
    if n > 0 then
        cat:add('\r\nProxy-Status: ')
        cat:add(txn.sf:hostname())
        for i = 1, n do
            local v = select(i, ...)
            cat:add(v)
        end
    end
    cat:add('\r\nContent-Length: 0\r\nConnection: close\r\n\r\n')
    txn.res:send(cat:dump())
    core.done(ret)
end

local function req_lines(txn)
    local offset = 0
    local first = true
    return function()
        while true do
            local line = txn.req:line(offset)
            -- line might be:
            --   nil
            --   txn request timeout without data
            if type(line) ~= 'string' or line:sub(-1) ~= '\n' then
                common_res(txn, act.INVALID, '408 Request Timeout')
            end
            offset = offset + #line
            if line ~= '\r\n' and line ~= '\n' then
                first = false
                return line
            end
            if not first then
                if txn.req:remove(0, offset) ~= offset then
                    core.done(act.ERROR)
                end
                return nil
            end
        end
    end
end

local ipv4_reg = must_regex([[^\d+(?:\.\d+)*$]], true)
local domain_reg = must_regex([=[^(?:[-_[:alnum:]]+\.)*[[:alpha:]][-[:alnum:]]{0,61}[[:alnum:]]$]=], true)

local function parse_host(txn, authority)
    while true do
        local port = txn.c:port_only(authority)
        if port <= 0 or port >= 65536 then
            break
        end
        local host = txn.c:host_only(authority)
        if host:byte(1) == 91 and host:byte(-1) == 93 then
            if host:find(':') == nil then break end
            local ip = host:sub(2, -2)
            if ip:find('/') or not core.parse_addr(ip) then break end
            txn:set_var('req.dst_ip', ip)
            txn:set_var('req.dst_type', 'IPv6')
        elseif ipv4_reg:match(host) then
            if not core.parse_addr(host) then break end
            txn:set_var('req.dst_ip', host)
            txn:set_var('req.dst_type', 'IPv4')
        elseif #host < 256 and domain_reg:match(host) then
            txn:set_var('req.dst_domain', host)
            txn:set_var('req.dst_type', 'domain')
        else
            break
        end
        txn:set_var('req.dst_port', port)
        return act.CONTINUE
    end
    common_res(txn, act.INVALID, '400 Bad Request', '; details="invalid host: ', authority, '"')
end

local req_line_reg = must_regex([=[^[[:space:]]*([[:alpha:]]+)[[:space:]]+([^[:space:]]+)[[:space:]]+(HTTP/[^[:space:]]+)[[:space:]]*$]=], true)
local http_body_reg = must_regex([[^(?:Content-Length|Transfer-Encoding)\s*:]], false)

core.register_action('http-req-connect', { 'tcp-req' }, function(txn)
    local iter = req_lines(txn)
    local st, list = req_line_reg:match(iter())
    if not st then common_res(txn, act.INVALID, '400 Bad Request') end
    if list[2] ~= 'CONNECT' then
        common_res(txn, act.INVALID, '501 Not Implemented')
    end
    for line in iter do
        if http_body_reg:match(line) then
            common_res(txn, act.INVALID, '400 Bad Request')
        end
    end
    return parse_host(txn, list[3])
end)

core.register_action('deny', { 'tcp-req', 'tcp-res' }, function(txn, ...) common_res(txn, act.DENY, ...) end, 1)
core.register_action('deny-status', { 'tcp-req', 'tcp-res' }, function(txn, ...) common_res(txn, act.DENY, ...) end, 2)

core.register_action('error', { 'tcp-req', 'tcp-res' }, function(txn, ...) common_res(txn, act.ERROR, ...) end, 1)
core.register_action('error-status', { 'tcp-req', 'tcp-res' }, function(txn, ...) common_res(txn, act.ERROR, ...) end, 2)

local chars = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'

core.register_action('http-res-connect', { 'tcp-res' }, function(txn)
    local cat = core.concat()
    cat:add('HTTP/1.1 200 Connection Established\r\nDate: ')
    cat:add(txn.sc:http_date(txn.f:date()))
    cat:add('\r\nETag: W/"')
    for _ = 1, txn.f:rand(49) + 16 do
        local idx = 1 + txn.f:rand(#chars)
        cat:add(chars:sub(idx, idx))
    end
    cat:add('"\r\nProxy-Status: ')
    cat:add(txn.sf:hostname())
    local bc_dst = txn.sf:bc_dst()
    if bc_dst:find(':') then
        cat:add('; next-hop=[')
        cat:add(bc_dst)
        cat:add(']:')
    else
        cat:add('; next-hop=')
        cat:add(bc_dst)
        cat:add(':')
    end
    cat:add(txn.sf:bc_dst_port())
    local bc_src = txn.sf:bc_src()
    if bc_src:find(':') then
        cat:add('; details="src=[')
        cat:add(bc_src)
        cat:add(']:')
    else
        cat:add('; details="src=')
        cat:add(bc_src)
        cat:add(':')
    end
    cat:add(txn.sf:bc_src_port())
    cat:add('"\r\n\r\n')
    local reply = cat:dump()
    if txn.res:send(reply) ~= #reply then
        return act.ERROR
    end
    return act.CONTINUE
end)
