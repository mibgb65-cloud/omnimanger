# Account Secret Vault

一个可部署到 Cloudflare Workers 的账号信息保险箱。邮箱、密码、2FA TOTP 种子、恢复码和备注会在浏览器内用主密码加密；Cloudflare KV 只保存加密后的 envelope。

这个项目适合自托管，也可以把部署后的页面链接分享给别人使用。用户注册登录后，会拥有自己的加密保险箱。

## 安全模型

- 登录密码的原文不发送到 Worker。浏览器会先派生登录用的 `authSecret`，Worker 再对它做 PBKDF2 后保存。
- 同一个登录密码也在浏览器内用于派生 AES-GCM 密钥，解密保险箱。
- KV 里只有密文；没有主密码就无法解密。
- Worker 保存用户记录、session 签名数据和保险箱密文。
- 如果主密码丢失，保险箱无法恢复。
- 同一个保险箱里同时保存密码和 2FA 会降低隔离性，建议另外离线保存 Google 恢复码。
- 不建议把这个项目当作公开 SaaS 服务直接开放注册；公开分享会消耗你的 Cloudflare KV 配额。

## 本地运行

1. 启动本地 Worker：

   ```powershell
   npm run dev
   ```

2. 新建 `.dev.vars`：

   ```powershell
   Copy-Item .dev.vars.example .dev.vars
   ```

3. 把 `.dev.vars` 里的 `SESSION_SECRET` 换成一个长随机字符串。

4. 打开 `http://localhost:8787`，注册邮箱和密码后开始使用。

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

4. 设置 session 签名 secret：

   ```powershell
   wrangler secret put SESSION_SECRET
   ```

5. 部署：

   ```powershell
   npm run deploy
   ```

## 使用

- 第一次打开时用邮箱和密码注册，会创建一个新保险箱。
- 后续用同一个邮箱和密码登录。
- 可以直接分享你的站点地址，其他人注册自己的账号后会存到自己的保险箱。
- 2FA 字段填写 Google Authenticator / Authy 导出的 TOTP secret 后，页面会显示当前 6 位验证码。

## GitHub 发布建议

- 不要提交 `.dev.vars`、`.wrangler/`、Cloudflare API token、真实账号信息或导出的密文备份。
- 第一次公开前确认 `wrangler.toml` 里的 KV namespace id 是示例值或你愿意公开的配置。
- 如果你分享自己的部署链接，提醒对方使用自己的邮箱和强密码。
