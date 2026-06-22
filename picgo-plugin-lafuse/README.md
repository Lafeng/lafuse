# picgo-plugin-lafuse

PicGo 的 Lafuse 上传器。

## 配置

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
