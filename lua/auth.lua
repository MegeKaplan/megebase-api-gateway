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

-- check authorization header
local auth_header = ngx.var.http_authorization
if not auth_header or not auth_header:find("Bearer ") then
    return send_unauthorized("Missing or invalid Authorization header")
end

-- get token
local token = auth_header:match("Bearer%s+(.+)")
if not token then
    return send_unauthorized("Invalid Bearer token format")
end

-- get jwt secret
local jwt_secret = os.getenv("JWT_SECRET")
if not jwt_secret then
    return send_unauthorized("JWT_SECRET not set")
end

-- verify token
local jwt_obj = jwt:verify(jwt_secret, token)
if not jwt_obj.verified then
    return send_unauthorized("Invalid or expired token")
end

-- get claims
local claims = jwt_obj.payload
if not claims.user_id then
    return send_unauthorized("Missing user_id in token claims")
end

-- set headers for user information
ngx.req.set_header("X-User-Id", claims.user_id)
ngx.req.set_header("X-User-Email", claims.email or "")
