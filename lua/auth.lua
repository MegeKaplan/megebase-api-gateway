local cjson = require "cjson"
local jwt = require "resty.jwt"

-- handle preflight options request
if ngx.req.get_method() == "OPTIONS" then
    ngx.status = 204
    ngx.header["Access-Control-Allow-Origin"] = "*"
    ngx.header["Access-Control-Allow-Methods"] = "GET, POST, PUT, PATCH, DELETE, OPTIONS"
    ngx.header["Access-Control-Allow-Headers"] = "Authorization, Content-Type, X-User-Id, X-Client-Id"
    return ngx.exit(204)
end

-- standard function to send unauthorized response
local function send_unauthorized(message)
    ngx.status = ngx.HTTP_UNAUTHORIZED
    ngx.header["Content-Type"] = "application/json"
    ngx.say(cjson.encode({
        error = "UNAUTHORIZED",
        message = message
    }))
    return ngx.exit(ngx.HTTP_UNAUTHORIZED)
end

-- get require_auth variable
local require_auth = ngx.var.require_auth ~= "0"

-- check authorization header
local auth_header = ngx.var.http_authorization
if not auth_header or not auth_header:find("Bearer ") then
    if require_auth then return send_unauthorized("Missing or invalid Authorization header") end
end

-- get token
local token = auth_header and auth_header:match("Bearer%s+(.+)")
if not token then
    if require_auth then return send_unauthorized("Invalid Bearer token format") end
end

-- get jwt secret
local jwt_secret = os.getenv("JWT_SECRET")
if not jwt_secret then
    if require_auth then return send_unauthorized("JWT_SECRET not set") end
end

-- verify token
local jwt_obj = token and jwt:verify(jwt_secret, token)
if jwt_obj and not jwt_obj.verified then
    if require_auth then return send_unauthorized("Invalid or expired token") end
end

-- get claims
local claims = jwt_obj and jwt_obj.payload
if claims and not claims.user_id then
    if require_auth then return send_unauthorized("Missing user_id in token claims") end
end

-- set headers for user information
if claims and claims.user_id then
    ngx.req.set_header("X-User-Id", claims.user_id)
    ngx.req.set_header("X-User-Email", claims.email or "")
end
