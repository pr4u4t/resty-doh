local bu64      = require "ngx.base64"
local utils     = require "utils"
local resolver  = require "resolver".nsresolve
local band      = bit.band
local rshift    = bit.rshift
local lshift    = bit.lshift
local char      = string.char
local byte      = string.byte
local rand      = math.random
local gsub      = string.gsub
local DOT_CHAR  = byte(".")

local _M        = {}

local STATUS   = {
        [200]     = "OK",
        [500]     = "Internal Server Error"
}

local function encode_name(s)
    return char(#s) .. s
end

local function gen_id(self)
    return rand(0, 65535)   -- two bytes
end

local function build_request(qname, id, no_recurse, opts)
    local qtype
    
    if opts then
        qtype = opts.qtype
    end 
    
    if not qtype then
        qtype = 1  -- A record
    end 
    
    local ident_hi = char(rshift(id, 8)) 
    local ident_lo = char(band(id, 0xff))
    
    local flags
    if no_recurse then
        flags = "\0\0"
    else
        flags = "\1\0"
    end 
    
    local nqs = "\0\1"
    local nan = "\0\0"
    local nns = "\0\0"
    local nar = "\0\0"
    local typ = char(rshift(qtype, 8), band(qtype, 0xff))
    local class = "\0\1"    -- the Internet class
    
    if byte(qname, 1) == DOT_CHAR then
        return nil, "bad name"
    end 
    
    local name = gsub(qname, "([^.]+)%.?", encode_name) .. '\0'
    
    local len = #ident_hi + #ident_lo + #flags + #nqs 
                + #nan + #nns + #nar + #name + #typ + #class
    
    return {
        ident_hi, ident_lo, flags, nqs, nan, nns, nar,
        name, typ, class
    }, len
end

function _M:parseRequest(data)
    local tmp = utils.explode(data,"\r\n")
    local first = utils.explode(tmp[1]," ")
    local uriargs = utils.explode(first[2],"?")
    local args = utils.explode(uriargs[2],"&")
    
    local request = { 
        method  = first[1], 
        uri     = uriargs[1], 
        proto   = first[3],
        args    = {}, 
        header  = {}
    }
    
    if type(args) == "table" then
        for k,v in pairs(args) do
        local kv = utils.explode(v,"=")
        request.args[kv[1]] = kv[2]
        end
    end
    
    for i=2,#tmp-2  do
        local kv = utils.explode(tmp[i],": ")
        request.header[kv[1]] = kv[2]
    end
    
    return request
end

function _M:prepareResponse(code,data,len)    
    local tmp = {
        ["Date"]            = os.date("%a, %d %b %Y %H:%m:%s",ngx.time()),
        ["Content-Type"]    = "application/dns-message",
        ["Connection"]      = "close"
    }
    
    if len then
        tmp["Content-Length"] = len
    end
    
    local response = "HTTP/1.1 "..code.." "..STATUS[code].."\r\n"
    
    for k,v in pairs(tmp) do
        response = response..k..": "..v.."\r\n"
    end
    
    if data then
        response = response.."\r\n"..data
    end
    
    return response
end

function _M:serveRequest()
    local down   = ngx.req.socket(true)
    local reader = down:receiveuntil("\r\n\r\n", { inclusive = true })
    local buffer = ''
    
    local data, err, partial = reader()
    if not data then
        if err then
            ngx.log(ngx.ERR,"Failed to read from downstream with error: ", err)
            ngx.exit(ngx.OK)
        end
    end
    
    local request = self:parseRequest(data)
    
    if request.method == "GET" then
        local domain = bu64.decode_base64url(request.args.dns)
        
        local up = ngx.socket.tcp()
        local ok, err = up:connect("127.0.0.1",53)
        
        if not ok then
            ngx.log(ngx.ERR, "Failed to connect to upstream with error: ", err)
            down:send(prepareResponse(500))
            down:close()
            ngx.exit(ngx.OK)
        end
        
        local data, len = build_request(domain, gen_id(), true)
        
        local len_hi = char(rshift(len, 8)) 
        local len_lo = char(band(len, 0xff))
        
        local bytes, err = up:send({len_hi, len_lo, data})
        
        if err then
           ngx.log(ngx.ERR,"Failed to send data to upstream with error: ", err)
           ngx.exit(ngx.OK)
        end
        
        local data, err, partial = up:receive(2)
        
        if err then
            ngx.log(ngx.ERR,"Failed to receive from upstream with error: ", err)
            ngx.exit(ngx.OK)
        end
        
        if not data then
            ngx.log(ngx.ERR,"Received empty response from upstream")
            ngx.exit(ngx.OK)
        end
        
        len_hi = byte(data, 1)
        len_lo = byte(data, 2)
        len = lshift(len_hi, 8) + len_lo
        
        local data, err, partial = up:receive(len)
        
        if err then
            ngx.log(ngx.ERR,"Failed to receive data from upstream with error: ", err)
            ngx.exit(ngx.OK)
        end
        
        up:close()
        
        local resp = self:prepareResponse(200,data,len)
        local bytes, err = down:send(resp)
        
        if err then
            ngx.log(ngx.ERR,"Failed to send data to downstream with error: ", err)
            ngx.exit(ngx.OK)
        end
        
        ngx.exit(ngx.OK)
    elseif request.method == "POST" then
        local len = request.header["Content-Length"]
        if not len then
            down:send(prepareResponse(500))
            down:close()
            ngx.exit(ngx.OK) 
        end
        
        local data, err, partial = down:receive(len)
        if not data and err then
            ngx.log(ngx.ERR, "Failed to receive data from down stream with error: ", err)
            down:send(prepareResponse(500))
            down:close()
            ngx.exit(ngx.OK)
        end
        
        local up = ngx.socket.tcp()
        local ok, err = up:connect("127.0.0.1",53)
        
        if not ok then
            ngx.log(ngx.ERR,"Failed to connect to upstream with error: ", err)
            down:send(prepareResponse(500))
            down:close()
            ngx.exit(ngx.OK)
        end
        
        local len_hi = char(rshift(len, 8)) 
        local len_lo = char(band(len, 0xff))
        
        local bytes, err = up:send({len_hi, len_lo, data})
        
        if err then
           ngx.log(ngx.ERR,"Failed to send data to upstream with error: ", err)
           ngx.exit(ngx.OK)
        end
        
        local data, err, partial = up:receive(2)

        if err then
           ngx.log(ngx.ERR, "Failed to receive data from upstream with error: ", err)
           ngx.exit(ngx.OK)
        end

        if not data then
            ngx.log(ngx.ERR,"Received empty response from upstream")
            ngx.exit(ngx.OK)
        end
        
        len_hi = byte(data, 1)
        len_lo = byte(data, 2)
        len = lshift(len_hi, 8) + len_lo
        
        local data, err, partial = up:receive(len)
        
        if err then
            ngx.log(ngx.ERR,"Failed to receive data from upstream with error: ", err)
            ngx.exit(ngx.OK)
        end
        
        if not data then
            ngx.log(ngx.ERR,"Received empty response from upstream")
            ngx.exit(ngx.OK)
        end
        
        up:close()
        local resp = self:prepareResponse(200,data,len)
        local bytes, err = down:send(resp)
        
        if err then
           ngx.log(ngx.ERR, "Failed to send data to downstream with error: ", err)
           ngx.exit(ngx.OK)
        end
        
        ngx.exit(ngx.OK)
    end
end

local function init()
    return true
end

if not init() then
   return nil 
end

return _M
