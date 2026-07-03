# Account Secret Vault

一个可部署到 Cloudflare Workers 的账号信息保险箱。邮箱、密码、2FA TOTP 种子、恢复码和备注会在浏览器内用主密码加密；Cloudflare KV 只保存加密后的 envelope。

这个项目适合自托管，也可以把部署后的页面链接分享给别人使用。用户注册登录后，会拥有自己的加密保险箱。默认不开放公开注册，只有主管理员可以在登录后的管理面板里开启或关闭注册。

## 安全模型

- 登录密码的原文不发送到 Worker。浏览器会先派生登录用的 `authSecret`，Worker 再对它做 PBKDF2 后保存。
- 同一个登录密码也在浏览器内用于派生 AES-GCM 密钥，解密保险箱。
- KV 里只有密文；没有主密码就无法解密。
- Worker 保存用户记录、session 签名数据和保险箱密文。
- 注册默认关闭。`ADMIN_EMAIL` 对应的主管理员账号可以注册并控制是否开放新用户注册。
- Worker 对注册、登录、保险箱读写和管理员设置做基础 KV 限流。
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

3. 把 `.dev.vars` 里的 `SESSION_SECRET` 换成一个长随机字符串，并把 `ADMIN_EMAIL` 改成主管理员邮箱。

4. 打开 `http://localhost:8787`，先用 `ADMIN_EMAIL` 对应邮箱注册主管理员账号。

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

5. 设置主管理员邮箱：

   ```powershell
   wrangler secret put ADMIN_EMAIL
   ```

6. 部署：

   ```powershell
   npm run deploy
   ```

## 使用

- 第一次打开时先用主管理员邮箱注册，会创建主管理员保险箱。
- 注册默认关闭。主管理员登录后可以在“管理员设置”里开放或关闭新用户注册。
- 后续用同一个邮箱和密码登录。
- 可以直接分享你的站点地址。只有在主管理员开放注册后，其他人才能注册自己的账号。
- 2FA 字段填写 Google Authenticator / Authy 导出的 TOTP secret 后，页面会显示当前 6 位验证码。

## 内置限流

当前版本使用 Cloudflare KV 做基础固定窗口限流：

- 注册：每个 IP 每小时 5 次，每个邮箱每小时 3 次。
- 登录：每个 IP 每 15 分钟 30 次，每个邮箱每 15 分钟 10 次。
- 保险箱读取：每个用户每分钟 120 次。
- 保险箱写入：每个用户每分钟 60 次。
- 管理员设置：每个管理员每分钟 20 次。

KV 限流不是强一致计数器，适合挡普通误用和低成本刷请求；如果公开给更多人使用，建议再加 Cloudflare Turnstile 或 Cloudflare WAF Rate Limiting。

## GitHub 发布建议

- 不要提交 `.dev.vars`、`.wrangler/`、Cloudflare API token、真实账号信息或导出的密文备份。
- 第一次公开前确认 `wrangler.toml` 里的 KV namespace id 是示例值或你愿意公开的配置。
- 如果你分享自己的部署链接，先确认注册开关状态，并提醒对方使用自己的邮箱和强密码。
