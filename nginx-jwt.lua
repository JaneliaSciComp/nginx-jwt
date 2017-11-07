local jwt = require "resty.jwt"
local cjson = require "cjson"
local basexx = require "basexx"

local logToken = os.getenv("LOG_TOKEN")
if logToken == nil then
    logToken = false
else
    logToken = string.lower(logToken)
    if logToken == "true" or logToken == "1" then
        logToken = true
    else
        logToken = false
    end
end

local secret = os.getenv("JWT_SECRET")

local authHeader = os.getenv("AUTHORIZATION_HEADER")
if authHeader == "" or authHeader == nil then
    authHeader = "Authorization"
end

local authTokenPrefix = os.getenv("AUTHORIZATION_PREFIX")
if authTokenPrefix == nil then
    authTokenPrefix = "Bearer"
end

assert(secret ~= nil, "Environment variable JWT_SECRET not set")

if os.getenv("JWT_SECRET_IS_BASE64_ENCODED") == 'true' then
    -- convert from URL-safe Base64 to Base64
    local r = #secret % 4
    if r == 2 then
        secret = secret .. "=="
    elseif r == 3 then
        secret = secret .. "="
    end
    secret = string.gsub(secret, "-", "+")
    secret = string.gsub(secret, "_", "/")

    -- convert from Base64 to UTF-8 string
    secret = basexx.from_base64(secret)
end


-- Helper Funtions
function get_token()
    -- require Authorization request header
    local auth_header = ngx.req.get_headers()[authHeader]

    local token;

    if auth_header == nil then
	token = ngx.var.arg_access_token
	if token == nil then
            ngx.log(ngx.WARN, "No Authorization header")
            ngx.exit(ngx.HTTP_UNAUTHORIZED)
        end
    end

    if token == nil then
        
        if (logToken ~= false) then
            ngx.log(ngx.INFO, "Authorization: " .. auth_header)
        end

        -- require Bearer token
        if authTokenPrefix ~= nil and authTokenPrefix ~= "" then
            local _
            _, _, token = string.find(auth_header, authTokenPrefix .. "%s+(.+)")
        else
            token = auth_header
        end

    end

    if token == nil then
        ngx.log(ngx.WARN, "Missing token")
        ngx.exit(ngx.HTTP_UNAUTHORIZED)
    end

    if (logToken ~= false) then
        ngx.log(ngx.INFO, "Token: " .. token)
    end

    return token
end

function validate_jwt(token)
    -- require valid JWT
    local jwt_obj = jwt:verify(secret, token, 0)
    if jwt_obj.verified == false then
        ngx.log(ngx.WARN, "Invalid token: ".. jwt_obj.reason)
        ngx.exit(ngx.HTTP_UNAUTHORIZED)
    end

    if (logToken ~= false) then
        ngx.log(ngx.INFO, "JWT: " .. cjson.encode(jwt_obj))
    end

    return jwt_obj
end


-- Returned Class
local M = {}

function M.auth(claim_specs, header_specs)

    local token         = get_token()
    local jwt_obj       = validate_jwt(token)

    -- optionally require specific claims
    if claim_specs ~= nil then
        -- make sure they passed a Table
        if type(claim_specs) ~= 'table' then
            ngx.log(ngx.STDERR, "Configuration error: claim_specs arg must be a table")
            ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
        end

        -- process each claim
        local blocking_claim = ""
        local spec_actions
        for claim, spec in pairs(claim_specs) do
            -- make sure token actually contains the claim
            local claim_value = jwt_obj.payload[claim]
            if claim_value == nil then
                blocking_claim = claim .. " (missing)"
                break
            end

            spec_actions = spec_actions or {
                -- claim spec is a string (pattern)
                ["string"] = function (pattern, val)
                    return string.match(val, pattern) ~= nil
                end,

                -- claim spec is a predicate function
                ["function"] = function (func, val)
                    -- convert truthy to true/false
                    if func(val) then
                        return true
                    else
                        return false
                    end
                end
            }

            local spec_action = spec_actions[type(spec)]

            -- make sure claim spec is a supported type
            if spec_action == nil then
                ngx.log(ngx.STDERR, "Configuration error: claim_specs arg claim '" .. claim .. "' must be a string or a function")
                ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
            end

            -- make sure token claim value satisfies the claim spec
            if not spec_action(spec, claim_value) then
                blocking_claim = claim
                break
            end
        end

        if blocking_claim ~= "" then
            ngx.log(ngx.WARN, "User did not satisfy claim: ".. blocking_claim)
            ngx.exit(ngx.HTTP_UNAUTHORIZED)
        end
    end

    -- optionally add specific headers
    if header_specs ~= nil then
        -- make sure they passed a Table
        if type(header_specs) ~= 'table' then
            ngx.log(ngx.STDERR, "Configuration error: header_specs arg must be a table")
            ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
        end

        local blocking_claim = ""
        local spec_actions
        for claim, spec in pairs(header_specs) do
            local claim_value = jwt_obj.payload[claim]

            spec_actions = spec_actions or {
                -- claim spec is a string
                ["string"] = function (header, val)
                    return header;
                end,

                -- claim spec is a predicate function
                ["function"] = function (func, val)
                    return func(val)
                end
            }

            local spec_action = spec_actions[type(spec)]

            -- make sure claim spec is a supported type
            if spec_action == nil then
                ngx.log(ngx.STDERR, "Configuration error: header_specs arg claim '" .. claim .. "' must be a string or a function")
                ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
            end

            -- make sure token claim value satisfies the claim spec
            local header = spec_action(spec, claim_value)
            if header ~= nil and string.sub(header, 1, 1) == "~" then
                -- optional header if empty string, ignore
                ngx.req.clear_header(string.sub(header, 2))
            elseif header == nil or (header ~= nil and claim_value == nil) then
                blocking_claim = claim .. " (missing)"
            else
                ngx.req.set_header(header, claim_value)
            end
        end

        if blocking_claim ~= "" then
            ngx.log(ngx.WARN, "User did not satisfy claim: ".. blocking_claim)
            ngx.exit(ngx.HTTP_UNAUTHORIZED)
        end
    end
end

function M.get_payload()
    local token     = get_token()
    local jwt_obj   = validate_jwt(token)

    return jwt_obj.payload
end

function M.table_contains(table, item)
    for _, value in pairs(table) do
        if value == item then return true end
    end
    return false
end

function M.make_optional_header(header)
    return function (val)
        if val ~= nil then
            return header
        else
            return "~" .. header
        end
    end
end

return M
