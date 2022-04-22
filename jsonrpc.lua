local mix_log = mix.log
local mix_DEBUG = mix.DEBUG
local json_encode = mix.json_encode
local json_decode = mix.json_decode

local _M = {}
local EOL = "\n"
local max_package_len = 65535

function _M.input(buf)
    if buf:length() > max_package_len then
        mix_log(mix_DEBUG, "exceeding max package len")
        return -1
    end

    local pos = string.find(buf:tostring(), EOL, 1, true)
    if not pos then
        return 0
    end

    return pos
end

function _M.decode(str, conn)
    local json = string.sub(str, 1, string.len(str) - string.len(EOL))
    local tb, err = json_decode(json)
    if err then
        conn:close()
        return nil
    end
    if tb["method"] == nil or tb["params"] == nil then
        conn:close()
        return nil
    end
    return tb
end

function _M.encode(str)
    return str .. EOL
end

function _M.encode_table(tb)
    local str, err = json_encode(tb)
    if err then
        return nil, err
    end
    return str .. EOL, nil
end

return _M
