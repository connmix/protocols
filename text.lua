local mix_log = mix.log
local mix_DEBUG = mix.DEBUG

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

function _M.decode(str)
    return string.sub(str, 1, string.len(str) - string.len(EOL))
end

function _M.encode(str)
    return str .. EOL
end

return _M
