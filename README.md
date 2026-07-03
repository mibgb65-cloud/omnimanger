# Account Secret Vault

一个可部署到 Cloudflare Workers 的账号信息保险箱。邮箱、密码、2FA TOTP 种子、恢复码和备注会在浏览器内用主密码加密；Cloudflare KV 只保存加密后的 envelope。

这个项目适合自托管，也可以把部署后的页面链接分享给别人使用。分享链接时只分享站点地址或 `?vault=保险箱ID`，不要分享主密码或同步令牌。

## 安全模型

- 主密码只在浏览器内用于派生 AES-GCM 密钥，不发送到 Worker。
- 每个保险箱有自己的 ID 和同步令牌。第一次远端保存会把该同步令牌的 SHA-256 哈希绑定到这个保险箱。
- KV 里只有密文；没有主密码就无法解密。
- Worker 会在请求时看到同步令牌，但不会保存同步令牌明文。
- 如果主密码丢失，保险箱无法恢复。
- 同一个保险箱里同时保存密码和 2FA 会降低隔离性，建议另外离线保存 Google 恢复码。
- 不建议把这个项目当作公开 SaaS 服务直接开放注册；公开分享会消耗你的 Cloudflare KV 配额。

## 本地运行

1. 启动本地 Worker：

   ```powershell
   npm run dev
   ```

2. 打开 `http://localhost:8787`。

3. 点击“生成”得到保险箱 ID，输入主密码和一个长随机同步令牌。

本地模式只写当前浏览器，不需要同步令牌。

## 部署到 Cloudflare

1. 登录 Wrangler：

   ```powershell
   wrangler login
   ```

2. 创建 KV namespace：

   ```powershell
   wrangler kv namespace create VAULT
   ```

3. 把命令输出里的 `id` 填到 `wrangler.toml` 的 `[[kv_namespaces]]` 里。

4. 部署：

   ```powershell
   npm run deploy
   ```

## 使用

- 第一次打开时输入保险箱 ID、主密码和同步令牌，会创建一个新保险箱。
- 后续用同一个保险箱 ID、主密码和同步令牌解锁。
- 你可以分享 `https://your-worker.example.workers.dev/?vault=你的保险箱ID`，但同步令牌和主密码必须单独安全传递。
- 2FA 字段填写 Google Authenticator / Authy 导出的 TOTP secret 后，页面会显示当前 6 位验证码。
- “本地模式”只保存到当前浏览器，不同步到 Cloudflare。

## GitHub 发布建议

- 不要提交 `.dev.vars`、`.wrangler/`、Cloudflare API token、真实账号信息或导出的密文备份。
- 第一次公开前确认 `wrangler.toml` 里的 KV namespace id 是示例值或你愿意公开的配置。
- 如果你要让别人自己部署，保持仓库公开即可；如果你要分享你的部署链接，提醒对方使用自己的保险箱 ID、主密码和同步令牌。
