# Lafuse

**Lafuse** 是基于 Cloudflare 生态（Workers + R2 + D1）构建的高性能边缘对象存储解决方案。它实现了从上传、分发到管理的纯边缘化闭环，提供极致的低延迟体验与企业级安全保障。

## 核心亮点

- **边缘原生架构**：摒弃传统回源链路，数据流转全在 Cloudflare 全球边缘节点完成，实现毫秒级响应。
- **极致性能与解耦**：前后端分离设计，结合 Cache API 与智能 TTL 策略，最大限度降低存储读取成本与访问延迟。
- **安全与风控**：内置 KV 级暴力破解防御、请求限流与严格的权限隔离，确保资产安全无忧。
- **现代化交互**：支持拖拽上传、剪贴板粘贴、懒加载预览及多格式链接一键复制，生产力拉满。

## 快速部署

### 1. 环境准备
确保拥有 Cloudflare 账号，并已启用 R2 存储桶与 D1 数据库。

### 2. 开发与部署

**本地开发**
```bash
npx wrangler dev --env dev
```

**生产发布**
```bash
npx wrangler deploy --env production
```

### 3.变量配置
在 Cloudflare Dashboard 或 `wrangler.toml` 中配置以下环境变量：

| 变量名 | 必填 | 描述 |
| :--- | :---: | :--- |
| `R2_BUCKET` | 是 | 绑定的 R2 存储桶名称 |
| `DATABASE` | 是 | 绑定的 D1 数据库变量名 |
| `USERNAME` / `PASSWORD` | 是 | 管理后台登录凭证 |
| `ADMIN_PATH` | 是 | 管理后台入口路径（如 `admin`） |
| `DOMAIN` | 是 | 自定义域名（用于生成文件链接） |
| `ENABLE_AUTH` | 否 | 是否开启访客访问鉴权（默认 `false`） |
| `MAX_SIZE_MB` | 否 | 单文件上传大小限制（默认 `10`） |

## License
MIT
