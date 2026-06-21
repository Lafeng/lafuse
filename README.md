# Lafuse

Lafuse 是一个基于 Cloudflare Workers、R2、D1 和 KV 的轻量资源图库。当前默认采用低成本模式：媒体访问尽量绕过 Worker，图库查询避免额外计数，上传链路默认不做查重和缩略图。

## 部署

本地开发：

```bash
npx wrangler dev
```

新建 D1 数据库后初始化：

```bash
npx wrangler d1 execute d1media --local --file scripts/schema.sql
```

已有数据库升级：

```bash
npx wrangler d1 migrations apply d1media --local
npx wrangler d1 migrations apply d1media --env production
```

生产发布：

```bash
npx wrangler secret put AUTH_SALT --env production
npx wrangler deploy --env production
```

## 配置

| 变量名 | 必填 | 默认值 | 说明 |
| :--- | :---: | :--- | :--- |
| `R2_BUCKET` | 是 | - | R2 存储桶绑定 |
| `DATABASE` | 是 | - | D1 数据库绑定 |
| `KV_NAMESPACE` | 是 | - | 登录失败限流 KV |
| `DOMAIN` | 是 | - | Worker 应用域名 |
| `AUTH_SALT` | 是 | - | 会话和密码散列盐，生产必须用 secret |
| `MEDIA_PUBLIC_ORIGIN` | 生产低成本模式必填 | - | R2 公开域名或自定义域名，用于让媒体文件绕过 Worker |
| `LOW_COST_MODE` | 否 | `1` | 开启低成本默认策略 |
| `MAX_SIZE_MB` | 否 | `10` | 单文件上传大小限制 |
| `ENABLE_UPLOAD_DEDUPE` | 否 | 低成本 `0` | 上传前 SHA-256 查重，会增加 D1 读请求 |
| `HASH_MAX_MB` | 否 | 低成本 `20` | 启用查重时的最大 hash 文件大小 |
| `ENABLE_THUMBNAILS` | 否 | 低成本 `0` | 上传时生成缩略图，会增加 R2 写入和存储 |
| `ENABLE_VIDEO_THUMBNAILS` | 否 | `0` | 视频缩略图，默认关闭 |
| `ENABLE_TOTAL_COUNT` | 否 | 低成本 `0` | 图库读取总数，会增加一次 D1 查询 |
| `SEARCH_MODE` | 否 | `prefix` | `prefix` 使用索引前缀搜索；`contains` 支持包含搜索但更贵 |
| `SEARCH_MIN_LENGTH` | 否 | `2` | 触发搜索的最小字符数 |
| `ALLOW_WORKER_MEDIA_PROXY` | 否 | 本地自动开启 | 生产强制允许 `/i/*`、`/t/*` 走 Worker 代理，仅调试建议使用 |

生产环境不要把 `AUTH_SALT` 写入 `wrangler.toml`，使用 `wrangler secret put AUTH_SALT --env production`。

## 低成本策略

- 媒体 URL 默认指向 `MEDIA_PUBLIC_ORIGIN`，图片和文件访问不进入 Worker。
- 低成本模式下 `/i/*`、`/t/*` 的 Worker 代理在生产默认关闭，避免错误配置导致每次看图都计 Worker 请求。
- 图库使用游标分页，避免 `OFFSET`。
- 默认不读取总数，列表接口只返回当前页和下一页游标。
- 默认不生成缩略图，图库图片直接使用原图 URL 预览。
- 默认不做上传前查重，避免每个文件额外一次 `/api.exists` 和 D1 查询。
- 搜索默认使用 `original_name_lc` 前缀范围查询，避免 `LIKE '%keyword%'` 扫描。
- 上传者筛选来源改为 `users` 表，不再从 `media` 表 `DISTINCT username`。
- schema 变更通过 `migrations/` 执行，不在请求路径里做 `PRAGMA` 和 `CREATE INDEX`。

## 账号

用户账号保存在 D1 的 `users` 表中。密码散列为：

```text
sha256(AUTH_SALT + ":" + password)
```

示例中的 hash 请用 `gen_user.sh` 按当前 `AUTH_SALT` 重新生成，不要提交真实用户 hash：

```sql
INSERT INTO users (username, password_hash, role)
VALUES ('admin', '<sha256-auth-salt-password>', 'admin');
```

## License

MIT
