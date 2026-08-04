# Cap for Netlify

将 [Cap](https://github.com/tiagozip/cap) CAPTCHA 替代方案部署到 Netlify Functions，使用 Netlify Postgres (Neon) 作为数据库。

## 快速部署

### 1. 安装依赖

```bash
cd netlify-deploy
npm install
```

### 2. 在 Netlify 创建站点

```bash
netlify deploy
```

或通过 Netlify 后台连接 Git 仓库。

### 3. 连接 Supabase 数据库

在 Netlify 后台：
1. 进入站点 → **Integrations** → **Supabase**
2. 点击 **Connect**，通过 OAuth 授权连接你的 Supabase 账户
3. 选择你的 Supabase 项目
4. 框架选择 **Other**，前缀留空
5. 点击 **Save**

Netlify 会自动注入以下环境变量：
- `SUPABASE_DATABASE_URL` — PostgreSQL 连接字符串（项目自动读取此变量）
- `SUPABASE_SERVICE_ROLE_KEY`
- `SUPABASE_ANON_KEY`
- `SUPABASE_JWT_SECRET`

> **注意**：Supabase 免费版数据库在 1 周无活动后会暂停，发起请求即可自动唤醒。

### 4. 设置环境变量

在 Netlify 后台 → **Site settings** → **Environment variables**：

| 变量 | 必填 | 说明 |
|------|------|------|
| `ADMIN_KEY` | 是 | 管理面板登录密钥（至少 12 个字符） |
| `SUPABASE_DATABASE_URL` | 自动 | 连接 Supabase 扩展后自动注入 |
| `CORS_ORIGIN` | 否 | 允许的来源（逗号分隔，`*` 或留空允许全部） |
| `DEMO_MODE` | 否 | 设为 `true` 开启演示模式（无需鉴权） |
| `RSW_BITS` | 否 | RSW 密钥位数（默认 2048） |

### 5. 初始化数据库

部署后，访问任意 API 端点（如 `https://你的站点.netlify.app/api/health`）会自动创建数据库表。

或手动执行：

```bash
SUPABASE_DATABASE_URL=你的连接字符串 node netlify/functions/api/_init-db.mjs
```

### 6. 开始使用

1. 访问 `https://你的站点.netlify.app/login.html`
2. 输入 `ADMIN_KEY` 登录
3. 创建 site key
4. 在你的网站集成 Cap widget

## API 端点

### 面向终端用户

| 方法 | 路径 | 说明 |
|------|------|------|
| POST | `/api/:siteKey/challenge` | 获取验证挑战 |
| POST | `/api/:siteKey/redeem` | 提交验证结果 |

### 面向后端服务

| 方法 | 路径 | 说明 |
|------|------|------|
| POST | `/api/v0/siteverify` | 验证 token（一次性消费） |

**siteverify 参数：**
```json
{
  "secret": "sk-你的secret密钥",
  "response": "redeem返回的token"
}
```

### 管理面板 API（需鉴权）

| 方法 | 路径 | 说明 |
|------|------|------|
| POST | `/api/login` | 登录 |
| GET | `/api/keys` | 获取所有 site keys |
| POST | `/api/keys` | 创建 site key |
| GET | `/api/keys/:siteKey` | 获取 key 详情与统计 |
| PUT | `/api/keys/:siteKey/config` | 更新 key 配置 |
| DELETE | `/api/keys/:siteKey` | 删除 key |
| POST | `/api/keys/:siteKey/rotate-secret` | 轮换 secret |
| GET | `/api/keys/:siteKey/geo-stats` | 获取地理统计 |
| GET/POST | `/api/keys/:siteKey/blocked-ips` | 获取/添加 IP 封禁 |
| POST | `/api/keys/:siteKey/unblock-ip` | 解封 IP |
| GET/PUT | `/api/settings/headers` | IP/Country/ASN 头设置 |
| GET/PUT | `/api/settings/ratelimit` | 速率限制设置 |
| GET/PUT | `/api/settings/cors` | CORS 设置 |
| GET/PUT | `/api/settings/filtering` | 过滤设置 |
| GET | `/api/settings/sessions` | 会话列表 |
| GET/POST | `/api/settings/apikeys` | API keys 管理 |
| GET | `/api/settings/rsw` | RSW 密钥状态 |
| GET | `/api/about` | 系统信息 |
| GET | `/api/health` | 健康检查 |

## 前端集成示例

### HTML

```html
<script src="https://cdn.jsdelivr.net/npm/@cap.js/widget"></script>
<cap-widget data-cap-api-endpoint="https://你的站点.netlify.app/api/你的siteKey"></cap-widget>
```

### 后端验证 (Node.js)

```javascript
const res = await fetch("https://你的站点.netlify.app/api/v0/siteverify", {
  method: "POST",
  headers: { "content-type": "application/json" },
  body: JSON.stringify({ secret: process.env.CAP_SECRET, response: token }),
});
const { success } = await res.json();
```

## 与原版的区别

| 特性 | 原版 (standalone) | Netlify 版 |
|------|-------------------|------------|
| 运行时 | Bun + Elysia | Node.js + Hono (Netlify Functions) |
| 数据库 | Redis | PostgreSQL (Netlify DB / Neon) |
| 密码哈希 | Bun.password (argon2) | bcryptjs |
| 速率限制 | Redis INCR + EXPIRE | PostgreSQL upsert |
| IP 数据库 | 本地 MaxMind .mmdb | 仅支持 header 传入 |
| 长驻任务 | setInterval 刷新 | 按需从 DB 加载 |
| 数据过期 | Redis TTL | 惰性清理 + TIMESTAMPTZ |

## 项目结构

```
netlify-deploy/
├── netlify.toml              # Netlify 配置
├── package.json
├── .env.example
├── public/                   # 前端静态文件
│   ├── index.html            # 管理面板
│   ├── login.html            # 登录页
│   ├── tester.html           # 测试工具
│   ├── js/dashboard.js       # 管理面板 JS
│   └── assets/               # CSS, 字体, 图表库, 国旗
└── netlify/
    └── functions/
        └── api/
            ├── api.js        # 主入口 (Hono handler)
            ├── _db.js        # PostgreSQL 数据库适配器
            ├── _schema.sql   # 数据库表结构
            ├── _crypto.js    # 密码哈希工具
            ├── _auth.js      # 鉴权模块
            ├── _cap.js       # CAPTCHA 挑战/验证路由
            ├── _server.js    # 管理面板 API 路由
            ├── _siteverify.js # siteverify 路由
            ├── _ratelimit.js # 速率限制模块
            ├── _settings.js  # 设置缓存
            ├── _rsw.js       # RSW 密钥对管理
            └── _init-db.mjs  # 数据库初始化脚本
```
