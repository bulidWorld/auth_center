# 认证中心接入文档

## 概述

认证中心基于 LDAP 提供统一认证，支持四种接入方式：

| 方式 | 场景 | 协议 |
|---|---|---|
| **API Token** | 服务间后端调用，无浏览器参与 | REST API + JWT |
| **OAuth 2.0 SSO** | 浏览器 Web 应用，用户跳转登录 | Authorization Code + PKCE |
| **LDAP 用户查询** | 代理查询 LDAP 用户信息 | REST API |
| **Internal Token** | 服务间签发/验证自定义 JWT | REST API + API Key |

**基础信息**

- 认证中心地址：`http://<auth-host>:10532`
- JWT 签名算法：RS256
- 公钥获取：`GET /.well-known/jwks.json`

---

## 方式一：API Token 接入（推荐服务间调用）

### 流程

```
外部服务                    认证中心
  |                            |
  |  POST /api/login           |
  |  {username, password} ---->|
  |                            |  LDAP 认证
  |  {access_token,            |
  |   refresh_token}   <------|
  |                            |
  |  GET /some-resource        |
  |  Authorization: Bearer <token>
  |                            |  本地验证 JWT 或回调 /api/verify
  |  返回数据 <----------------|
```

### 1. 登录获取 Token

**请求**

```http
POST /api/login HTTP/1.1
Host: auth-host:10532
Content-Type: application/json

{
  "username": "zhiwenxia",
  "password": "Zwx199310"
}
```

**成功响应 (200)**

```json

{"access_token":"eyJhbGc...",
"token_type":"Bearer","expires_in":3600,
"refresh_token":"63a624...",
"scope":"api",
"user":{"username":"zhiwenxia",
"displayName":"zhiwenxia",
"email":"xxxx",
"dn":"uid=zhiwenxia,ou=people,dc=naze"}
}
```

**失败响应 (401)**

```json
{
  "error": "invalid_credentials",
  "error_description": "Invalid credentials"
}
```

### 2. 使用 Token 访问受保护资源

后续请求在 Header 中携带 token：

```http
GET /some-api HTTP/1.1
Host: your-service
Authorization: Bearer eyJhbGciOiJSUzI1NiIs...
```

你的服务有两种方式验证 token：

#### 方式 A：直接验证 JWT 签名（推荐，无需回调认证中心）

```javascript
// 1. 获取公钥（启动时获取一次，缓存）
const jwks = await fetch('http://auth-host:10532/.well-known/jwks.json').then(r => r.json());

// 2. 用 jose 库验证（Node.js）
const { jwtVerify } = require('jose');
const result = await jwtVerify(accessToken, jwks.keys[0]);
// result.payload.sub => "uid=zhiwenxia,ou=people,dc=naze"
// result.payload.preferred_username => "zhiwenxia"
```

```python
# Python 示例
import jwt, requests

jwks = requests.get("http://auth-host:10532/.well-known/jwks.json").json()
public_key = jwt.algorithms.RSAAlgorithm.from_jwk(jwks["keys"][0])
decoded = jwt.decode(access_token, public_key, algorithms=["RS256"], issuer="auth-center")
```

#### 方式 B：调用认证中心验证接口

```http
GET /api/verify HTTP/1.1
Host: auth-host:10532
Authorization: Bearer eyJhbGciOiJSUzI1NiIs...
```

```json
{
  "valid": true,
  "user": {
    "username": "zhiwenxia",
    "displayName": "zhiwenxia",
    "sub": "uid=zhiwenxia,ou=people,dc=naze"
  },
  "expires_at": "2026-05-07T09:19:48.000Z",
  "scope": "api"
}
```

### 3. 刷新 Token

access_token 默认有效期 1 小时，过期后用 refresh_token 换新 token：

```http
POST /api/refresh HTTP/1.1
Host: auth-host:10532
Content-Type: application/json

{
  "refresh_token": "2211b0b22df368310f510cab..."
}
```

返回结构同登录接口。旧 refresh_token 刷新后失效，需保存新返回的 refresh_token。

### 4. 吊销 Token

```http
POST /api/revoke HTTP/1.1
Host: auth-host:10532
Authorization: Bearer eyJhbGciOiJSUzI1NiIs...
Content-Type: application/json

{
  "token": "eyJhbGciOiJSUzI1NiIs..."   // 可选，不传则吊销当前 token
}
```

---

## 方式二：OAuth 2.0 SSO 接入（浏览器 Web 应用）

### 前置条件：注册 OAuth 客户端

联系认证中心管理员注册你的应用，获取 `client_id` 和 `client_secret`。

**管理员调用注册接口**（需 Admin API Key，在 `.env` 中配置 `ADMIN_API_KEY`）：

```http
POST /admin/clients HTTP/1.1
Host: auth-host:10532
Content-Type: application/json
X-Admin-API-Key: <你的管理员密钥>

{
  "client_name": "MyApp",
  "redirect_uris": ["https://myapp.example.com/callback"],
  "grant_types": ["authorization_code"],
  "scope": "openid profile api"
}
```

**响应**（请保存 `client_id` 和 `client_secret`，secret 仅返回一次）：

```json
{
  "client_id": "550e8400-e29b-41d4-a716-446655440000",
  "client_secret": "ac_7f8g9h0i1j2k3l4m5n6o7p8q9r0s1t2u3v4w",
  "client_name": "MyApp",
  "redirect_uris": ["https://myapp.example.com/callback"],
  "grant_types": ["authorization_code"],
  "scope": "openid profile api",
  "created_at": "2026-05-08T06:00:00.000Z"
}
```

**管理员管理接口**：

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/admin/clients` | 列出所有客户端 |
| DELETE | `/admin/clients/:id` | 删除客户端 |

> 以上接口均为管理员接口，调用时需提供 `X-Admin-API-Key` 头。

### 完整流程

```
浏览器            你的服务              认证中心
  |                  |                    |
  |-- 访问页面 ------>|                    |
  |<- 302 登录 ------|                    |
  |-----> /authorize?client_id=xxx       |
  |                  |                    | 显示登录页（首次）
  |<--- 登录表单 -----|                    |
  |-- 提交密码 ------>|                    |
  |                  |  LDAP 认证          |
  |<- 302 redirect ---|--------------------|
  |    ?code=AUTH_CODE                  |
  |-- 带 code 回调 -->|                    |
  |                  | POST /token        |
  |                  | {code, verifier} ->|
  |                  | {access_token}  <--|
  |                  |                    |
  |  登录完成，后续使用 token            |
```

### 步骤 1：生成 PKCE

```javascript
const crypto = require('crypto');

// 生成 code_verifier（43-128 位随机字符串）
const codeVerifier = crypto.randomBytes(32).toString('base64url');

// 生成 code_challenge（SHA256(code_verifier) 的 base64url 编码）
const codeChallenge = crypto
  .createHash('sha256')
  .update(codeVerifier)
  .digest('base64url');

// state 用于防止 CSRF
const state = crypto.randomBytes(16).toString('hex');

// 存储到 session，步骤 2 需要
session.codeVerifier = codeVerifier;
session.state = state;
```

### 步骤 2：重定向到认证中心

```http
HTTP/1.1 302 Found
Location: http://auth-host:10532/authorize?response_type=code
  &client_id=你的client_id
  &redirect_uri=http://your-app/callback
  &state=步骤1生成的state
  &code_challenge=步骤1生成的codeChallenge
  &code_challenge_method=S256
```

### 步骤 3：处理回调

用户登录后，认证中心重定向到你的 `redirect_uri`：

```http
GET /callback?code=AUTH_CODE&state=STATE HTTP/1.1
Host: your-app
```

验证 state 匹配后，用 code 换取 token：

```http
POST /token HTTP/1.1
Host: auth-host:10532
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code
&code=AUTH_CODE
&redirect_uri=http://your-app/callback
&client_id=你的client_id
&client_secret=你的client_secret
&code_verifier=步骤1生成的codeVerifier    


   
```

**成功响应**

```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIs...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "xxx",
  "scope": "openid profile api",
  "id_token": "eyJhbGciOiJSUzI1NiIs..."
}
```

### SSO 效果

用户在任何已注册的应用登录过一次后，访问其他应用时认证中心检测到已有 session，直接生成新的 auth_code 并跳转回应用，**用户不会看到登录页**。

---

## 方式三：LDAP 用户查询

直接通过 REST API 查询 LDAP 用户信息，无需直接连接 LDAP 服务器。

### 查询所有用户

```http
GET /api/users HTTP/1.1
Host: auth-host:10532
Authorization: Bearer <valid_token>
```

```json
[
  {
    "username": "zhiwenxia",
    "displayName": "zhiwenxia",
    "email": null,
    "dn": "uid=zhiwenxia,ou=people,dc=naze"
  },
  {
    "username": "admin",
    "displayName": "Administrator",
    "email": "admin@example.com",
    "dn": "uid=admin,ou=people,dc=naze"
  }
]
```

### 查询单个用户

```http
GET /api/users/:username HTTP/1.1
Host: auth-host:10532
Authorization: Bearer <valid_token>
```

```json
{
  "username": "zhiwenxia",
  "displayName": "zhiwenxia",
  "email": null,
  "dn": "uid=zhiwenxia,ou=people,dc=naze"
}
```

用户不存在返回 `404`：

```json
{
  "error": "user_not_found",
  "error_description": "User not found"
}
```

---

## 方式四：Internal Token 签名/验证（服务间调用）

> 需要 `X-API-Key` 头，值为 `.env` 中配置的 `ADMIN_API_KEY`。

### 签发 Token

为内部服务签发自定义 payload 的 JWT，无需 LDAP 认证。

**请求**

```http
POST /api/internal/token/sign HTTP/1.1
Host: auth-host:10532
Content-Type: application/json
X-API-Key: <你的API Key>

{
  "payload": {
    "sub": "service:my-app",
    "role": "worker",
    "custom_field": "value"
  },
  "ttl": 86400
}
```

- `payload`（必填）：自定义 JWT payload 对象，会自动补充 `iss`、`iat`、`exp`、`jti`
- `ttl`（可选）：token 有效期（秒），不传则使用默认值（3600）

**成功响应 (200)**

```json
{
  "token": "eyJhbGciOiJSUzI1NiIs..."
}
```

### 验证 Token

验证 JWT 签名和有效期，返回解码后的 payload。

**请求**

```http
POST /api/internal/token/verify HTTP/1.1
Host: auth-host:10532
Content-Type: application/json
X-API-Key: <你的API Key>

{
  "token": "eyJhbGciOiJSUzI1NiIs..."
}
```

**成功响应 (200)**

```json
{
  "valid": true,
  "payload": {
    "sub": "service:my-app",
    "role": "worker",
    "custom_field": "value",
    "iss": "auth-center",
    "iat": 1710259200,
    "exp": 1710345600,
    "jti": "uuid"
  }
}
```

**失败响应 (401)**

```json
{
  "valid": false,
  "error": "token_expired"
}
```

### 典型使用场景

```
服务A                           认证中心                      服务B
  |                               |                            |
  | POST /api/internal/token/sign |                            |
  | X-API-Key + payload -------->|                            |
  | <--- { token } -------------|                            |
  |                               |                            |
  | 调用服务B，携带 token ------>|                            |
  |                               |                            |
  |                               |  服务B 回调验证 token       |
  |                               |  POST /api/internal/token/verify
  |                               |  <--- { valid, payload }   |
```

---

## 接口一览

### API Token 接口

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/api/login` | LDAP 认证，获取 token |
| GET | `/api/verify` | 验证 token 有效性 |
| POST | `/api/revoke` | 吊销 token |
| POST | `/api/refresh` | 刷新 token |

### LDAP 用户查询接口

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/users` | 查询所有 LDAP 用户 |
| GET | `/api/users/:username` | 查询指定用户 |

> 用户查询接口需要提供有效的 Bearer token。

### Admin 管理接口

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/admin/clients` | 注册 OAuth 客户端（需 Admin API Key） |
| GET | `/admin/clients` | 列出所有客户端 |
| DELETE | `/admin/clients/:id` | 删除客户端 |

> Admin 接口需在 Header 中传递 `X-Admin-API-Key`。

### Internal 内部接口

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/api/internal/token/sign` | 签发自定义 JWT（需 API Key） |
| POST | `/api/internal/token/verify` | 验证 JWT 签名及有效期（需 API Key） |

> Internal 接口需在 Header 中传递 `X-API-Key`。

### OAuth 2.0 接口

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/authorize` | 授权入口（浏览器跳转） |
| POST | `/token` | 换取 token |
| GET | `/userinfo` | 获取用户信息 |
| GET | `/.well-known/openid-configuration` | OIDC 发现文档 |
| GET | `/.well-known/jwks.json` | RSA 公钥（JWKS） |

### 错误码

| 错误码 | 含义 |
|---|---|
| `invalid_credentials` | 用户名或密码错误 |
| `token_expired` | Token 已过期 |
| `token_revoked` | Token 已被吊销 |
| `invalid_token` | Token 无效或格式错误 |
| `invalid_grant` | 授权码无效或已过期 |
| `invalid_client` | 客户端未注册或密钥错误 |
| `user_not_found` | 用户不存在 |
| `unauthorized` | API Key 缺失或无效 |

---

## 各语言接入示例

### Node.js

```javascript
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const fetch = require('node-fetch');

const AUTH_URL = 'http://auth-host:10532';

// 1. 登录
async function login(username, password) {
  const res = await fetch(`${AUTH_URL}/api/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password }),
  });
  return res.json();
}

// 2. 验证 token（直接验证 JWT，不回调认证中心）
const { jwtVerify } = require('jose');
async function verifyToken(token) {
  const jwks = await fetch(`${AUTH_URL}/.well-known/jwks.json`).then(r => r.json());
  const result = await jwtVerify(token, jwks.keys[0]);
  return result.payload;
}

// 3. 查询用户
async function getUser(username) {
  const token = (await login('admin', 'password')).access_token;
  const res = await fetch(`${AUTH_URL}/api/users/${username}`, {
    headers: { 'Authorization': `Bearer ${token}` },
  });
  return res.json();
}

// 4. 签发自定义 Token（服务间调用）
async function signServiceToken(payload, ttl, apiKey) {
  const res = await fetch(`${AUTH_URL}/api/internal/token/sign`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-API-Key': apiKey,
    },
    body: JSON.stringify({ payload, ttl }),
  });
  return res.json();
}

// 5. 验证 Token（服务间回调验证）
async function verifyServiceToken(token, apiKey) {
  const res = await fetch(`${AUTH_URL}/api/internal/token/verify`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-API-Key': apiKey,
    },
    body: JSON.stringify({ token }),
  });
  return res.json();
}
```

### Python

```python
import requests
import jwt

AUTH_URL = "http://auth-host:10532"

# 1. 登录
def login(username, password):
    res = requests.post(f"{AUTH_URL}/api/login", json={
        "username": username,
        "password": password,
    })
    res.raise_for_status()
    return res.json()

# 2. 验证 token（直接验证 JWT）
def verify_token(token):
    jwks = requests.get(f"{AUTH_URL}/.well-known/jwks.json").json()
    public_key = jwt.algorithms.RSAAlgorithm.from_jwk(jwks["keys"][0])
    decoded = jwt.decode(token, public_key, algorithms=["RS256"], issuer="auth-center")
    return decoded

# 3. 查询用户
def get_user(username, token):
    res = requests.get(
        f"{AUTH_URL}/api/users/{username}",
        headers={"Authorization": f"Bearer {token}"},
    )
    res.raise_for_status()
    return res.json()

# 4. 签发自定义 Token（服务间调用）
def sign_service_token(payload, ttl, api_key):
    res = requests.post(
        f"{AUTH_URL}/api/internal/token/sign",
        json={"payload": payload, "ttl": ttl},
        headers={"X-API-Key": api_key},
    )
    res.raise_for_status()
    return res.json()

# 5. 验证 Token（服务间回调验证）
def verify_service_token(token, api_key):
    res = requests.post(
        f"{AUTH_URL}/api/internal/token/verify",
        json={"token": token},
        headers={"X-API-Key": api_key},
    )
    res.raise_for_status()
    return res.json()
```

### cURL

```bash
# 登录
curl -X POST http://auth-host:10532/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"zhiwenxia","password":"Zwx199310"}'

# 验证
curl http://auth-host:10532/api/verify \
  -H "Authorization: Bearer <access_token>"

# 刷新
curl -X POST http://auth-host:10532/api/refresh \
  -H "Content-Type: application/json" \
  -d '{"refresh_token":"<refresh_token>"}'

# 吊销
curl -X POST http://auth-host:10532/api/revoke \
  -H "Authorization: Bearer <access_token>"

# 查询用户
curl http://auth-host:10532/api/users/zhiwenxia \
  -H "Authorization: Bearer <access_token>"

# 签发自定义 Token（服务间调用）
curl -X POST http://auth-host:10532/api/internal/token/sign \
  -H "Content-Type: application/json" \
  -H "X-API-Key: <api_key>" \
  -d '{"payload":{"sub":"service:my-app","role":"worker"},"ttl":86400}'

# 验证 Token
curl -X POST http://auth-host:10532/api/internal/token/verify \
  -H "Content-Type: application/json" \
  -H "X-API-Key: <api_key>" \
  -d '{"token":"<jwt_token>"}'
```

---

## 常见问题

**Q: Token 有效期多久？**
A: access_token 默认 1 小时，refresh_token 默认 7 天。过期后需刷新。

**Q: 多个服务共享同一个 token 吗？**
A: 是的。用户在一个服务登录后，session 存储在认证中心。访问其他服务时，认证中心检测到已有 session，直接签发新 token，无需重新输入密码。

**Q: 如何安全存储 refresh_token？**
A: 服务端的 refresh_token 应加密存储在数据库中。浏览器端建议存储在 httpOnly cookie 中。

**Q: JWT 验证需要每次回调认证中心吗？**
A: 不需要。JWT 使用 RS256 签名，服务端用公钥即可验证。只有需要检查吊销状态时才需要回调 `/api/verify`。

**Q: 密码错误会返回什么？**
A: `401 { "error": "invalid_credentials" }`。

**Q: 用户查询接口的认证要求？**
A: 需要提供有效的 Bearer token（通过 `/api/login` 获取）。
