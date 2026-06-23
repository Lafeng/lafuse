# picgo-plugin-lafuse

PicGo 的 Lafuse 上传器。

## 安装

PicGo Core 只会从 `~/.picgo/package.json` 的依赖项和 `~/.picgo/node_modules/` 加载 `picgo-plugin-*`。本地开发或私有使用时，把插件安装到 PicGo 配置目录：

```bash
cd ~/.picgo
npm install --legacy-peer-deps <repo-path>/picgo-plugin-lafuse
```

安装后确认上传器列表包含 `lafuse`：

```bash
node -e "const { PicGo } = require('picgo'); const p = new PicGo(require('node:path').join(process.env.HOME, '.picgo/config.json')); console.log(p.helper.uploader.getIdList())"
```

## 配置

可参考 `config.example.json`：

```json
{
  "picBed": {
    "uploader": "lafuse",
    "current": "lafuse",
    "lafuse": {
      "endpoint": "https://lafuse.example.com",
      "token": "lafuse_v1_xxxxxxxxxxxx_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    }
  },
  "picgoPlugins": {
    "picgo-plugin-lafuse": true
  }
}
```

`endpoint` 可以填写 Lafuse 站点根地址，也可以填写完整的 `/api/v1/upload` 地址。

## 上传

```bash
picgo u /path/to/image.png
```

成功后返回的 URL 应该指向你配置的 Lafuse 媒体公开域名，例如 `https://media.example.com/i/<id>.<ext>`。
