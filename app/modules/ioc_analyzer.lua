-- ioc_analysis.lua
-- Enterprise-level IOC analysis for file objects in Lua

local crypto = require("crypto") -- placeholder, depends on your Lua crypto lib
local yara = require("yara")     -- hypothetical Lua YARA binding

local ioc_database = {
    hashes = {
        ["d41d8cd98f00b204e9800998ecf8427e"] = "Known malware MD5 hash",
        -- Add more hashes here
    },
    filename_patterns = {
        ".*eviltool.*%.exe",
        ".*malicious_payload.*",
    },
    suspicious_strings = {
        "cmd.exe /c",
        "powershell -nop -w hidden",
        "CreateRemoteThread",
    }
}

local function calculate_hash(file_path, algo)
    -- This is a placeholder: use your Lua crypto lib or call out to system tools
    -- Example with OpenSSL: openssl dgst -sha256 filename
    local cmd = string.format("openssl dgst -%s %s", algo, file_path)
    local handle = io.popen(cmd)
    local result = handle:read("*a")
    handle:close()
    local hash = result:match("%w+%s*=%s*(%w+)")
    return hash and hash:lower() or nil
end

local function read_file(file_path)
    local f = io.open(file_path, "rb")
    if not f then return nil end
    local content = f:read("*all")
    f:close()
    return content
end

local function check_hashes(file_path)
    local matches = {}
    for _, algo in ipairs({"md5", "sha1", "sha256"}) do
        local h = calculate_hash(file_path, algo)
        if h and ioc_database.hashes[h] then
            table.insert(matches, {type="hash", algo=algo, value=h, description=ioc_database.hashes[h]})
        end
    end
    return matches
end

local function check_filename(filename)
    local matches = {}
    for _, pattern in ipairs(ioc_database.filename_patterns) do
        if filename:match(pattern) then
            table.insert(matches, {type="filename", pattern=pattern, description="Filename pattern matched"})
        end
    end
    return matches
end

local function check_suspicious_strings(file_content)
    local matches = {}
    for _, str in ipairs(ioc_database.suspicious_strings) do
        if file_content:find(str, 1, true) then -- plain find
            table.insert(matches, {type="string", value=str, description="Suspicious string detected"})
        end
    end
    return matches
end

local function check_yara_rules(file_path)
    -- Using a Lua YARA binding or external call to yara scanner
    local matches = {}
    local rules = yara.load_rules("ioc_rules/yara/malware_rules.yar")
    local scan_results = yara.scan_file(rules, file_path)
    for _, rule in ipairs(scan_results) do
        table.insert(matches, {type="yara", rule=rule.identifier, description="YARA rule matched"})
    end
    return matches
end

local function analyze_file(file_path)
    local results = {}
    local filename = file_path:match("^.+/(.+)$") or file_path

    -- 1. Hash checks
    local hash_matches = check_hashes(file_path)
    if #hash_matches > 0 then
        results.hashes = hash_matches
    end

    -- 2. Filename pattern checks
    local fname_matches = check_filename(filename)
    if #fname_matches > 0 then
        results.filename_patterns = fname_matches
    end

    -- 3. Suspicious string checks
    local content = read_file(file_path)
    if content then
        local str_matches = check_suspicious_strings(content)
        if #str_matches > 0 then
            results.suspicious_strings = str_matches
        end
    else
        results.error = "Failed to read file content"
    end

    -- 4. YARA scanning
    local yara_matches = check_yara_rules(file_path)
    if #yara_matches > 0 then
        results.yara = yara_matches
    end

    return results
end

-- Example usage:
-- local file_to_check = "/path/to/file.exe"
-- local report = analyze_file(file_to_check)
-- print(require('json').encode(report))

return {
    analyze_file = analyze_file
}

