#!/usr/bin/env lua

-- ZTE SMS Sender for OpenWrt
-- Dependencies:
-- Install required packages:
--   opkg install lua-sha2 luasocket lua-cjson lua-md5 lua-argparse
--
-- This script allows sending SMS messages through ZTE routers from OpenWrt

local http = require("socket.http")
local ltn12 = require("ltn12")
local json = require("cjson")
local sha256hex = require("sha2").sha256hex
local md5 = require("md5")
local argparse = require("argparse")

-- Function to encode hex
local function tohex(str)
    return (str:gsub('.', function(c)
        return string.format('%02X', string.byte(c))
    end))
end

-- Custom URL encode function that only encodes characters that need to be encoded
local function selective_url_encode(str)
    if not str then return "" end
    
    -- Only encode characters that need to be encoded in a URL
    -- Keep alphanumeric characters and some safe symbols as-is
    return string.gsub(str, "([^A-Za-z0-9_%.%-%~])", function(c)
        -- Convert to hex representation
        return string.format("%%%02X", string.byte(c))
    end)
end

-- Function to URL encode data
local function urlencode(data)
    local result = ""
    for k, v in pairs(data) do
        if result ~= "" then
            result = result .. "&"
        end
        
        -- Use our selective URL encoding
        result = result .. selective_url_encode(k) .. "=" .. selective_url_encode(tostring(v))
    end
    return result
end

-- Implementation of buildQuery function with custom encoding
local function buildQuery(params)
    local query = {}
    for k, v in pairs(params) do
        table.insert(query, selective_url_encode(k) .. "=" .. selective_url_encode(tostring(v)))
    end
    return table.concat(query, "&")
end

-- Main SMS sending class
local ZTESMS = {}
ZTESMS.__index = ZTESMS

function ZTESMS.new(router_ip, password)
    local self = setmetatable({}, ZTESMS)
    self.router_ip = router_ip
    self.password = password
    self.cookies = {}
    self.headers = {
        ["Referer"] = "http://" .. router_ip .. "/index.html",
        ["Accept"] = "application/json, text/javascript, */*; q=0.01",
        ["Content-Type"] = "application/x-www-form-urlencoded"
    }
    
    print("Connecting to router at " .. router_ip)
    
    -- Initialize version info during object creation
    self.wa_inner_version, self.cr_version = self:get_version_info()
    
    return self
end

function ZTESMS:send_get_command(cmd, params)
    local request_params = params or {}
    if cmd then
        request_params.cmd = cmd
    end
    request_params.isTest = "false"
    
    local query = buildQuery(request_params)
    local url = "http://" .. self.router_ip .. "/goform/goform_get_cmd_process?" .. query
    
    -- Debug info
    print("Sending GET request to: " .. url)
    
    -- Use LuaSocket's http library for GET requests
    local response_body = {}
    local headers = {}
    
    -- Copy our headers
    for k, v in pairs(self.headers) do
        headers[k] = v
    end
    
    -- Add cookies if any
    if self.cookies and next(self.cookies) then
        local cookie_str = ""
        for k, v in pairs(self.cookies) do
            if cookie_str ~= "" then cookie_str = cookie_str .. "; " end
            cookie_str = cookie_str .. k .. "=" .. v
        end
        headers["Cookie"] = cookie_str
    end
    
    -- Make the request
    local res, code, response_headers = http.request {
        url = url,
        headers = headers,
        sink = ltn12.sink.table(response_body)
    }
    
    if not res then
        print("HTTP GET request failed: " .. (code or "unknown error"))
        return nil
    end
    
    -- Process response
    local body = table.concat(response_body)
    
    -- Debug info
    print("Response code: " .. (code or "unknown"))
    print("Response body: " .. (body or "empty"))
    
    -- Parse JSON
    if body and body ~= "" then
        local success, result = pcall(json.decode, body)
        if success then
            return result
        else
            print("Error parsing JSON response: " .. result)
            return nil
        end
    end
    
    return nil
end

function ZTESMS:send_set_command(goformId, data, include_ad)
    local request_data = data or {}
    request_data.isTest = "false"
    request_data.goformId = goformId
    
    -- Add AD to request_data if needed
    if include_ad == nil or include_ad then
        request_data.AD = self:calculate_ad()
    end
    
    local encoded_data = urlencode(request_data)
    
    -- Debug information
    print("Sending POST request to: http://" .. self.router_ip .. "/goform/goform_set_cmd_process")
    print("POST data: " .. encoded_data)
    
    -- Add our cookies to the request if any exist
    local headers = {}
    for k, v in pairs(self.headers) do
        headers[k] = v
    end
    
    -- Add Content-Length header
    headers["Content-Length"] = tostring(#encoded_data)
    
    if self.cookies and next(self.cookies) then
        local cookie_str = ""
        for k, v in pairs(self.cookies) do
            if cookie_str ~= "" then cookie_str = cookie_str .. "; " end
            cookie_str = cookie_str .. k .. "=" .. v
        end
        headers["Cookie"] = cookie_str
        print("Sending cookies: " .. cookie_str)
    end
    
    -- Make the request
    local response_body = {}
    
    -- Use LuaSocket's built-in facility
    local res, code, response_headers = http.request {
        url = "http://" .. self.router_ip .. "/goform/goform_set_cmd_process",
        method = "POST",
        headers = headers,
        source = ltn12.source.string(encoded_data),
        sink = ltn12.sink.table(response_body)
    }
    
    -- Debug response information
    print("Response status: " .. (res and "OK" or "Failed") .. ", code: " .. (code or "unknown"))
    
    -- Check for and process cookies in the response
    if response_headers then
        for k, v in pairs(response_headers) do
            if k:lower() == "set-cookie" then
                print("Received Set-Cookie: " .. v)
                for cookie_name, cookie_value in v:gmatch("([^=]+)=([^;]+)") do
                    print("  Extracted cookie: " .. cookie_name .. " = " .. cookie_value)
                    self.cookies[cookie_name] = cookie_value
                    if cookie_name == "stok" then
                        self.stok = cookie_value
                        print("  Found stok cookie: " .. cookie_value)
                    end
                end
            end
        end
    end
    
    if not res then
        print("HTTP request error: " .. (code or "unknown"))
        return nil
    end
    
    if code ~= 200 then
        print("HTTP request failed with code: " .. code)
        return nil
    end
    
    -- Process the response body
    local body = table.concat(response_body)
    print("Response body: " .. (body or "empty"))
    
    -- Parse JSON
    if body and body ~= "" then
        local success, result = pcall(json.decode, body)
        if success then
            return result
        else
            print("Error parsing JSON response: " .. result)
            return nil
        end
    end
    
    return nil
end

function ZTESMS:get_LD()
    local result = self:send_get_command("LD")
    if result and result.LD then
        print("Got LD value: " .. result.LD)
        return result.LD:upper()
    else
        print("Failed to get LD value")
        return ""
    end
end

function ZTESMS:get_version_info()
    local params = {
        cmd = "cr_version,wa_inner_version",
        multi_data = "1"
    }
    local result = self:send_get_command(nil, params)
    if result then
        local wa_inner_version = result.wa_inner_version or ""
        local cr_version = result.cr_version or ""
        print("Device version: " .. wa_inner_version .. ", cr_version: " .. cr_version)
        return wa_inner_version, cr_version
    end
    return "", ""
end

function ZTESMS:get_rd()
    local result = self:send_get_command("RD")
    return result and result.RD or ""
end

function ZTESMS:hash_password(password, ld)
    -- Hash password with LD value as required by ZTE routers
    -- First hash the password with SHA-256
    local initial_hash = sha256hex(password):upper()
    -- Then hash the combination of hashed password and LD value
    local final_hash = sha256hex(initial_hash .. ld):upper()
    print("Hashed password: " .. final_hash)
    return final_hash
end

function ZTESMS:calculate_ad()
    -- Calculate AD verification code required for goform_set_cmd_process calls
    --
    -- The AD code is calculated by:
    -- 1. Concatenating wa_inner_version and cr_version and hashing with MD5
    -- 2. Getting the RD value from the router
    -- 3. Concatenating the version hash with RD and hashing again with MD5
    
    local version_string = self.wa_inner_version .. self.cr_version
    local version_hash = md5.sumhexa(version_string)
    
    -- Get RD value from router which is used as a nonce
    local router_rd = self:get_rd()
    
    -- Calculate final AD verification code by hashing version_hash + RD
    local combined_hash_input = version_hash .. router_rd
    local verification_code = md5.sumhexa(combined_hash_input)
    
    return verification_code
end

function ZTESMS:encode_message(message)
    -- Bitwise operations for Lua 5.1
    local function band(a, b)
        local result = 0
        local bitval = 1
        while a > 0 and b > 0 do
            if a % 2 == 1 and b % 2 == 1 then -- test least significant bits
                result = result + bitval      -- set bit in result
            end
            bitval = bitval * 2
            a = math.floor(a / 2)
            b = math.floor(b / 2)
        end
        return result
    end
    
    local function bor(a, b)
        local result = 0
        local bitval = 1
        while a > 0 or b > 0 do
            if a % 2 == 1 or b % 2 == 1 then
                result = result + bitval
            end
            bitval = bitval * 2
            a = math.floor(a / 2)
            b = math.floor(b / 2)
        end
        return result
    end
    
    local function lshift(a, b)
        return a * (2 ^ b)
    end
    
    local function rshift(a, b)
        return math.floor(a / (2 ^ b))
    end

    -- Convert UTF-8 string to UTF-16BE bytes
    local utf16_bytes = ""
    
    -- Process UTF-8 characters properly
    local i = 1
    while i <= #message do
        local byte = string.byte(message, i)
        local code_point
        local skip = false  -- Flag to skip the normal code point processing
        
        -- Determine UTF-8 sequence length and extract code point
        if byte < 128 then
            -- ASCII character (0-127)
            code_point = byte
            i = i + 1
        elseif byte >= 192 and byte < 224 then
            -- 2-byte sequence (128-2047)
            if i + 1 <= #message then
                local byte2 = string.byte(message, i + 1)
                code_point = bor(lshift(band(byte, 0x1F), 6), band(byte2, 0x3F))
                i = i + 2
            else
                -- Incomplete sequence, treat as replacement character
                code_point = 0xFFFD
                i = i + 1
            end
        elseif byte >= 224 and byte < 240 then
            -- 3-byte sequence (2048-65535)
            if i + 2 <= #message then
                local byte2 = string.byte(message, i + 1)
                local byte3 = string.byte(message, i + 2)
                code_point = bor(
                    lshift(band(byte, 0x0F), 12),
                    bor(
                        lshift(band(byte2, 0x3F), 6),
                        band(byte3, 0x3F)
                    )
                )
                i = i + 3
            else
                -- Incomplete sequence
                code_point = 0xFFFD
                i = i + 1
            end
        elseif byte >= 240 and byte < 248 then
            -- 4-byte sequence (65536-1114111)
            if i + 3 <= #message then
                local byte2 = string.byte(message, i + 1)
                local byte3 = string.byte(message, i + 2)
                local byte4 = string.byte(message, i + 3)
                
                -- Calculate code point
                code_point = bor(
                    lshift(band(byte, 0x07), 18),
                    bor(
                        lshift(band(byte2, 0x3F), 12),
                        bor(
                            lshift(band(byte3, 0x3F), 6),
                            band(byte4, 0x3F)
                        )
                    )
                )
                
                -- For characters outside BMP (> 0xFFFF), we need to use surrogate pairs
                if code_point > 0xFFFF then
                    -- Calculate surrogate pair
                    local surrogate = code_point - 0x10000
                    local high_surrogate = 0xD800 + rshift(surrogate, 10)
                    local low_surrogate = 0xDC00 + band(surrogate, 0x3FF)
                    
                    -- Add high surrogate (BE)
                    utf16_bytes = utf16_bytes .. string.char(
                        band(rshift(high_surrogate, 8), 0xFF),
                        band(high_surrogate, 0xFF)
                    )
                    
                    -- Add low surrogate (BE)
                    utf16_bytes = utf16_bytes .. string.char(
                        band(rshift(low_surrogate, 8), 0xFF),
                        band(low_surrogate, 0xFF)
                    )
                    
                    i = i + 4
                    skip = true  -- Skip the normal code point processing
                else
                    i = i + 4
                end
            else
                -- Incomplete sequence
                code_point = 0xFFFD
                i = i + 1
            end
        else
            -- Invalid UTF-8 byte, use replacement character
            code_point = 0xFFFD
            i = i + 1
        end
        
        -- Add the code point as UTF-16BE bytes if not skipped
        if not skip then
            utf16_bytes = utf16_bytes .. string.char(
                band(rshift(code_point, 8), 0xFF),
                band(code_point, 0xFF)
            )
        end
    end
    
    -- Convert to hex
    return tohex(utf16_bytes)
end

function ZTESMS:login()
    print("Logging in to router")
    
    -- Get LD value for password hashing
    local ld = self:get_LD()
    if not ld or ld == "" then
        print("Failed to get LD value, cannot login")
        return false
    end
    
    -- Hash the password with LD
    local hashed_password = self:hash_password(self.password, ld)
    print("Password hashed, attempting login...")
    
    -- Single-user login (older ZTE routers)
    local data = {password = hashed_password}
    local result = self:send_set_command("LOGIN", data, false)
    
    -- Check response directly
    if result and result.result == "0" then
        print("Login successful!")
        return true
    else
        -- Check for stok cookie as alternative success indicator
        if self.stok then
            print("Login successful via stok cookie!")
            return true
        else
            print("Login failed. Response: " .. (result and json.encode(result) or "nil"))
            return false
        end
    end
end

function ZTESMS:send_sms(phone_number, message)
    if not self:login() then
        return false
    end
    
    local data = {
        notCallback = "true",
        Number = phone_number,
        MessageBody = self:encode_message(message),
        ID = "-1",
        encode_type = "UNICODE",
    }
    
    local result = self:send_set_command("SEND_SMS", data)
    if result and result.result == "success" then
        print("SMS sent successfully to " .. phone_number)
        return true
    else
        print("Failed to send SMS: " .. (result and json.encode(result) or "Unknown error"))
        return false
    end
end

function ZTESMS:logout()
    local result = self:send_set_command("LOGOUT")
    
    if result and result.result == "success" then
        print("Logout successful")
        return true
    else
        print("Logout failed: " .. (result and json.encode(result) or "Unknown error"))
        return false
    end
end

-- Simple command line argument parser that doesn't rely on argparse features
local function parse_args()
    local parser = argparse("zte-sms-sender", "Send SMS messages through ZTE routers from OpenWrt")
    
    parser:option("-r --router", "Router IP address", "192.168.254.1")
    parser:option("-p --password", "Router password")
    parser:option("-n --number", "Phone number to send SMS to")
    parser:option("-m --message", "Message to send")

    local args = parser:parse()

    -- Manual validation for required arguments
    if not args.password then
        error("Missing required argument: password (-p)")
    end
    if not args.number then
        error("Missing required argument: number (-n)")
    end
    if not args.message then
        error("Missing required argument: message (-m)")
    end

    return args
end

-- Main execution
local function main()
    local args = parse_args()
    
    -- Initialize ZTE SMS sender
    local zte = ZTESMS.new(args.router, args.password)
    
    -- Send SMS
    local success = zte:send_sms(args.number, args.message)
    
    -- Logout
    if success then
        zte:logout()
    end
end

main()
