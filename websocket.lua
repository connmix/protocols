local mix_log = mix.log
local mix_DEBUG = mix.DEBUG
local str_lower = string.lower
local str_split = mix.str_split
local str_find = string.find
local sha1_bin = mix.sha1_bin
local base64 = mix.base64_encode
local bytes_tostring = mix.bytes_tostring
local bit = require "bit"
local band = bit.band
local bor = bit.bor
local char = string.char
local lshift = bit.lshift
local rshift = bit.rshift
local byte = string.byte
local bxor = bit.bxor
local sub = string.sub
local rand = math.random

local types = {
    [0x0] = "continuation",
    [0x1] = "text",
    [0x2] = "binary",
    [0x8] = "close",
    [0x9] = "ping",
    [0xa] = "pong",
}

local max_payload_len = 65535
local force_masking = false

local _M = {}
local EOL = "\r\n"

function _M.input(buf, conn, uri, on_handshake)
    --握手
    if not conn:context_value("__handshake") then
        return _M._handshake(buf, conn, uri, on_handshake)
    end

    --读取frame
    local pos, msg, typ, err = _M._read_frame(buf, max_payload_len, force_masking)
    if err then
        mix_log(mix_DEBUG, "recv frame error: " .. err)
    end
    if msg then
        conn:set_context_value("__last_frame", { data = msg, type = typ, finish = (err ~= "again") })
    end
    return pos
end

function _M.decode(conn)
    local frame = conn:context_value("__last_frame")
    if frame["type"] == "close" then
        conn:close();
    end
    return frame
end

function _M.encode(str)
    local frame, err = _M._build_frame(true, 0x1, #str, str, false)
    if not frame then
        mix_log(mix_DEBUG, "build frame error: " .. err)
        return nil
    end
    return frame
end

function _M._handshake(buf, conn, uri, on_handshake)
    local pos = string.find(buf:tostring(), EOL .. EOL, 1, true)
    if not pos then
        return 0
    end

    --解析headers
    local req_headers = {}
    for k, v in ipairs(str_split(buf:tostring(), EOL)) do
        if v ~= "" then
            if k == 1 then
                local arr = str_split(v, " ")
                if #arr == 3 then
                    req_headers["Method"] = arr[1]
                    req_headers["RequestUri"] = arr[2]
                    req_headers["ServerProtocol"] = arr[3]
                end
            else
                local arr = str_split(v, ": ")
                if #arr == 2 then
                    req_headers[arr[1]] = arr[2]
                end
            end
        end
    end

    --print(headers)

    --uri验证
    if string.find(req_headers["RequestUri"], uri) ~= 1 then
        mix_log(mix_DEBUG, "uri does not allow")
        return -1
    end

    -- 验证Websocket请求
    local http_ver = req_headers["ServerProtocol"]
    if not http_ver or http_ver ~= "HTTP/1.1" then
        mix_log(mix_DEBUG, "bad http version")
        return -1
    end

    local val = req_headers["Upgrade"]
    if not val or str_lower(val) ~= "websocket" then
        mix_log(mix_DEBUG, "bad \"upgrade\" request header: " .. tostring(val))
        return -1
    end

    val = req_headers["Connection"]
    if not val or not str_find(str_lower(val), "upgrade", 1, true) then
        mix_log(mix_DEBUG, "bad \"connection\" request header")
        return -1
    end

    local key = req_headers["Sec-WebSocket-Key"]
    if not key then
        mix_log(mix_DEBUG, "bad \"sec-websocket-key\" request header")
        return -1
    end

    local ver = req_headers["Sec-WebSocket-Version"]
    if not ver or ver ~= "13" then
        mix_log(mix_DEBUG, "bad \"sec-websocket-version\" request header")
        return -1
    end

    --握手响应
    local mix_header = {}
    mix_header["Server"] = "connmix"

    local protocols = req_headers["sec-websocket-protocol"]
    if protocols then
        mix_header["Sec-WebSocket-Protocol"] = protocols
    end

    mix_header["Upgrade"] = "websocket"
    mix_header["Connection"] = "Upgrade"

    local sha1 = sha1_bin(key .. "258EAFA5-E914-47DA-95CA-C5AB0DC85B11")
    local str, err = base64(sha1)
    if err then
        mix_log(mix_DEBUG, "base64 error: " .. err)
        return -1
    end
    mix_header["Sec-WebSocket-Accept"] = str

    --print(mix_header)

    local resp = "HTTP/1.1 101 Switching Protocols" .. EOL
    for k, v in pairs(mix_header) do
        resp = resp .. k .. ": " .. v .. EOL
    end
    resp = resp .. EOL

    --print(resp)
    err = conn:send(resp)
    if err then
        mix_log(mix_DEBUG, "conn send handshake error: " .. err)
        return -1
    end
    conn:clear_buffer()
    conn:set_context_value("__handshake", true)
    conn:set_context_value("headers", req_headers)

    if on_handshake ~= nil then
        on_handshake(req_headers, conn)
    end

    return 0
end

function _M._send_frame(conn, fin, opcode, payload, max_payload_len, masking)
    if not payload then
        payload = ""

    elseif type(payload) ~= "string" then
        payload = tostring(payload)
    end

    local payload_len = #payload

    if payload_len > max_payload_len then
        return nil, "payload too big"
    end

    if band(opcode, 0x8) ~= 0 then
        -- being a control frame
        if payload_len > 125 then
            return nil, "too much payload for control frame"
        end
        if not fin then
            return nil, "fragmented control frame"
        end
    end

    local frame, err = _M._build_frame(fin, opcode, payload_len, payload, masking)
    if not frame then
        return nil, "failed to build frame: " .. err
    end

    err = conn:send(frame)
    if err then
        mix_log(mix_DEBUG, "conn send frame error: " .. err)
        return nil, err
    end
    return true, nil
end

function _M.send_text(conn, data)
    return _M._send_frame(conn, true, 0x1, data, 65535, nil)
end

function _M.send_binary(conn, data)
    return _M._send_frame(conn, true, 0x2, data, 65535, nil)
end

function _M._build_frame(fin, opcode, payload_len, payload, masking)
    local fst
    if fin then
        fst = bor(0x80, opcode)
    else
        fst = opcode
    end

    local snd, extra_len_bytes
    if payload_len <= 125 then
        snd = payload_len
        extra_len_bytes = ""

    elseif payload_len <= 65535 then
        snd = 126
        extra_len_bytes = char(band(rshift(payload_len, 8), 0xff),
                band(payload_len, 0xff))

    else
        if band(payload_len, 0x7fffffff) < payload_len then
            return nil, "payload too big"
        end

        snd = 127
        -- XXX we only support 31-bit length here
        extra_len_bytes = char(0, 0, 0, 0, band(rshift(payload_len, 24), 0xff),
                band(rshift(payload_len, 16), 0xff),
                band(rshift(payload_len, 8), 0xff),
                band(payload_len, 0xff))
    end

    local masking_key
    if masking then
        -- set the mask bit
        snd = bor(snd, 0x80)
        local key = rand(0xffffffff)
        masking_key = char(band(rshift(key, 24), 0xff),
                band(rshift(key, 16), 0xff),
                band(rshift(key, 8), 0xff),
                band(key, 0xff))

        local bytes = {}
        for i = 1, payload_len do
            local b = bxor(byte(payload, i),
                    byte(masking_key, (i - 1) % 4 + 1))
            table.insert(bytes, b)
        end
        payload = bytes_tostring(bytes)
    else
        masking_key = ""
    end

    return char(fst, snd) .. extra_len_bytes .. masking_key .. payload
end

function _M._read_frame(buffer, max_payload_len, force_masking)
    local data, err = buffer:read(2)
    if not data then
        return 0, nil, nil, nil
    end

    local fst, snd = byte(data, 1, 2)

    local fin = band(fst, 0x80) ~= 0
    -- print("fin: ", fin)

    if band(fst, 0x70) ~= 0 then
        return -1, nil, nil, "bad RSV1, RSV2, or RSV3 bits"
    end

    local opcode = band(fst, 0x0f)
    -- print("opcode: ", tohex(opcode))

    if opcode >= 0x3 and opcode <= 0x7 then
        return -1, nil, nil, "reserved non-control frames"
    end

    if opcode >= 0xb and opcode <= 0xf then
        return -1, nil, nil, "reserved control frames"
    end

    local mask = band(snd, 0x80) ~= 0

    --mix_log(mix_DEBUG, "recv_frame: mask bit: ", mask and 1 or 0)

    if force_masking and not mask then
        return -1, nil, nil, "frame unmasked"
    end

    local payload_len = band(snd, 0x7f)
    -- print("payload len: ", payload_len)

    if payload_len == 126 then
        local data, err = buffer:read(2)
        if not data then
            return 0, nil, nil, nil
        end

        payload_len = bor(lshift(byte(data, 1), 8), byte(data, 2))

    elseif payload_len == 127 then
        local data, err = buffer:read(8)
        if not data then
            return 0, nil, nil, nil
        end

        if byte(data, 1) ~= 0
                or byte(data, 2) ~= 0
                or byte(data, 3) ~= 0
                or byte(data, 4) ~= 0
        then
            return -1, nil, nil, "payload len too large"
        end

        local fifth = byte(data, 5)
        if band(fifth, 0x80) ~= 0 then
            return -1, nil, nil, "payload len too large"
        end

        payload_len = bor(lshift(fifth, 24),
                lshift(byte(data, 6), 16),
                lshift(byte(data, 7), 8),
                byte(data, 8))
    end

    if band(opcode, 0x8) ~= 0 then
        -- being a control frame
        if payload_len > 125 then
            return -1, nil, nil, "too long payload for control frame"
        end

        if not fin then
            return -1, nil, nil, "fragmented control frame"
        end
    end

    -- print("payload len: ", payload_len, ", max payload len: ", max_payload_len)

    if payload_len > max_payload_len then
        return -1, nil, nil, "exceeding max payload len"
    end

    local rest
    if mask then
        rest = payload_len + 4

    else
        rest = payload_len
    end
    -- print("rest: ", rest)

    local data
    if rest > 0 then
        data, err = buffer:read(rest)
        if not data then
            return 0, nil, nil, nil
        end
    else
        data = ""
    end

    -- print("received rest")

    if opcode == 0x8 then
        -- being a close frame
        if payload_len > 0 then
            if payload_len < 2 then
                return -1, nil, nil, "close frame with a body must carry a 2-byte" .. " status code"
            end

            local msg, code
            if mask then
                local fst = bxor(byte(data, 4 + 1), byte(data, 1))
                local snd = bxor(byte(data, 4 + 2), byte(data, 2))
                code = bor(lshift(fst, 8), snd)

                if payload_len > 2 then
                    local bytes = {}
                    for i = 3, payload_len do
                        local b = bxor(byte(data, 4 + i),
                                byte(data, (i - 1) % 4 + 1))
                        table.insert(bytes, b)
                    end
                    msg = bytes_tostring(bytes)
                else
                    msg = ""
                end

            else
                local fst = byte(data, 1)
                local snd = byte(data, 2)
                code = bor(lshift(fst, 8), snd)

                -- print("parsing unmasked close frame payload: ", payload_len)

                if payload_len > 2 then
                    msg = sub(data, 3)

                else
                    msg = ""
                end
            end

            return buffer:position(), code .. "," .. msg, "close", nil
        end

        return buffer:position(), "", "close", nil
    end

    local msg
    if mask then
        local bytes = {}
        for i = 1, payload_len do
            local b = bxor(byte(data, 4 + i),
                    byte(data, (i - 1) % 4 + 1))
            table.insert(bytes, b)
        end
        msg = bytes_tostring(bytes)
    else
        msg = data
    end

    return buffer:position(), msg, types[opcode], not fin and "again" or nil
end

return _M
