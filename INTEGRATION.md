# 认证中心接入文档

## 概述

认证中心基于 LDAP 提供统一认证，支持三种接入方式：

| 方式 | 场景 | 协议 |
|---|---|---|
| **API Token** | 服务间后端调用，无浏览器参与 | REST API + JWT |
| **OAuth 2.0 SSO** | 浏览器 Web 应用，用户跳转登录 | Authorization Code + PKCE |
| **LDAP 用户查询** | 需要查询 LDAP 用户信息（搜索、获取详情） | REST API（内部代理 LDAP） |

**基础信息**

- 认证中心地址：`http://<auth-host>:10532`（Nginx 网关端口）
- 说明：Nginx 在 10532 端口反向代理到内部认证中心（Node.js 10531），外部服务统一使用 10532
- JWT 签名算法：RS256
- 公钥获取：`GET /.well-known/jwks.json`

---

## 架构说明

```
外部请求              Nginx:10532            认证中心 Node.js
  |                        |                    |
  |  POST /api/login ----->|  反向代理           |
  |                        |  ----------------->|  LDAP 认证
  |  {access_token} <------|                    |
  |                        |                    |
  |  GET /authorize ------>|  反向代理           |
  |                        |  ----------------->|  登录页 / SSO
  |  {access_token} <------|                    |
  |                        |                    |
  |  GET /api/users ------->|  反向代理           |
  |                        |  ----------------->|  LDAP 查询
```

- 认证中心 Node.js 内部监听 **10531** 端口
- Nginx 监听 **10532** 端口，反向代理到 10531
- **所有外部请求统一使用 `:10532`**，无需感知 10531

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
  |  后续请求携带 Bearer token  |
  |  或直接验证 JWT 签名        |
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

**成功响应**

```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIs...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "2211b0b22df368310f510cab...",
  "scope": "api",
  "user": {
    "username": "zhiwenxia",
    "displayName": "支文侠",
    "email": "zhiwenxia@naze"
  }
}
```

**失败响应** `401`

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

// 2. 用 jwt 库验证（以 Node.js 为例）
const decoded = jwt.verify(accessToken, publicKey, {
  algorithms: ['RS256'],
  issuer: 'auth-center',
});
// decoded.sub => "uid=zhiwenxia,ou=people,dc=naze"
// decoded.preferred_username => "zhiwenxia"
```

```python
# Python 示例
import jwt
public_key = """-----BEGIN PUBLIC KEY-----..."""  # 从 JWKS 获取
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
    "displayName": "支文侠",
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

{
  "token": "eyJhbGciOiJSUzI1NiIs..."   // 可选，不传则吊销当前 token
}
```

---

## 方式二：OAuth 2.0 SSO 接入（浏览器 Web 应用）

### 前置条件

联系认证中心管理员注册你的应用，获取 `client_id` 和 `client_secret`。

注册时需要提供：
- `client_name`：应用名称
- `redirect_uris`：登录成功后的回调地址列表（数组）

### 完整流程

```
浏览器            你的服务              认证中心
  |                  |                    |
  |-- 访问页面 ------>|                    |
  |<- 302 登录 ------|                    |
  |-----> /authorize?client_id=xxx       |
  |                  |                    | 显示登录页
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

## 方式三：LDAP 用户查询（代理）

认证中心内部代理 LDAP 连接，提供用户查询接口。外部服务无需直接连接 LDAP 服务器。

### 搜索用户

```http
GET /api/users?q=关键字&limit=50 HTTP/1.1
Host: auth-host:10532
```

参数：
- `q`：搜索关键字，匹配 uid、cn、mail、displayName 字段。为空则返回所有用户
- `limit`：返回数量上限，默认 50

**成功响应**

```json
{
  "total": 3,
  "users": [
    {
      "dn": "uid=zhiwenxia,ou=people,dc=naze",
      "username": "zhiwenxia",
      "displayName": "支文侠",
      "email": "zhiwenxia@naze",
      "groups": [],
      "objectClass": ["top", "person", "organizationalPerson", "inetOrgPerson"]
    },
    {
      "dn": "uid=zhangsan,ou=people,dc=naze",
      "username": "zhangsan",
      "displayName": "Zhang San",
      "email": "zhangsan@nazetecn.cn",
      "groups": [],
      "objectClass": ["top", "person", "organizationalPerson", "inetOrgPerson"]
    }
  ]
}
```

**示例**

```bash
# 搜索包含 "张" 的用户
curl "http://auth-host:10532/api/users?q=张"

# 获取所有用户
curl "http://auth-host:10532/api/users"

# 限制返回数量
curl "http://auth-host:10532/api/users?limit=10"
```

### 获取单个用户

```http
GET /api/users/:username HTTP/1.1
Host: auth-host:10532
```

**成功响应**

```json
{
  "dn": "uid=zhiwenxia,ou=people,dc=naze",
  "username": "zhiwenxia",
  "displayName": "支文侠",
  "email": "zhiwenxia@naze",
  "groups": [],
  "objectClass": ["top", "person", "organizationalPerson", "inetOrgPerson"]
}
```

**失败响应** `404`

```json
{
  "error": "not_found",
  "error_description": "User not found"
}
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
| GET | `/api/users` | 搜索用户（`?q=关键字&limit=50`） |
| GET | `/api/users/:username` | 获取单个用户详情 |

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
| `not_found` | 用户不存在 |
| `ldap_error` | LDAP 连接/查询失败 |

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

// 3. 搜索 LDAP 用户
async function searchUsers(keyword) {
  const res = await fetch(`${AUTH_URL}/api/users?q=${encodeURIComponent(keyword)}`);
  return res.json();
}

// 4. 获取单个用户
async function getUser(username) {
  const res = await fetch(`${AUTH_URL}/api/users/${encodeURIComponent(username)}`);
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

# 3. 搜索用户
def search_users(keyword=""):
    res = requests.get(f"{AUTH_URL}/api/users", params={"q": keyword})
    return res.json()

# 4. 获取单个用户
def get_user(username):
    res = requests.get(f"{AUTH_URL}/api/users/{username}")
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

# 搜索用户
curl "http://auth-host:10532/api/users?q=张"

# 获取用户
curl "http://auth-host:10532/api/users/zhiwenxia"
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

**Q: LDAP 用户查询接口需要认证吗？**
A: 当前不需要。如需保护，可在 Nginx 层添加 IP 白名单或接入 token 验证。
