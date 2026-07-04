# Account Secret Vault

一个可部署到 Cloudflare Workers 的账号信息保险箱。邮箱、密码、2FA TOTP 种子、恢复码和备注会在浏览器内用主密码加密；Cloudflare KV 只保存加密后的 envelope。

这个项目适合自托管，也可以把部署后的页面链接分享给别人使用。用户注册登录后，会拥有自己的加密保险箱。默认不开放公开注册，只有主管理员可以在登录后的管理面板里开启或关闭注册。

## 安全模型

- 登录密码的原文不发送到 Worker。浏览器会先用 PBKDF2 派生登录用的 `authSecret`，Worker 再用 `AUTH_PEPPER`/`SESSION_SECRET` 做 HMAC-SHA256 verifier。
- 旧账号如果还使用早期 salted SHA-256 或 PBKDF2 v2 verifier，成功登录后会自动升级到当前 HMAC verifier。
- 同一个登录密码也在浏览器内用于派生 AES-GCM 密钥，解密保险箱。
- KV 里只有密文；没有主密码就无法解密。
- Worker 保存用户记录、session 签名数据和保险箱密文。
- 注册默认关闭。`ADMIN_EMAIL` 对应的主管理员账号可以注册并控制是否开放新用户注册。
- 管理员可以生成一次性邀请链接，让注册关闭时的指定用户完成注册。
- Worker 对注册、登录、保险箱读写和管理员设置做基础 KV 限流。
- 保险箱保存和主密码修改都带 revision 校验，能发现常见的多设备旧版本覆盖。
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

3. 把 `.dev.vars` 里的 `SESSION_SECRET` 和 `AUTH_PEPPER` 换成不同的长随机字符串，并把 `ADMIN_EMAIL` 改成主管理员邮箱。

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

5. 设置登录 verifier pepper：

   ```powershell
   wrangler secret put AUTH_PEPPER
   ```

6. 设置主管理员邮箱：

   ```powershell
   wrangler secret put ADMIN_EMAIL
   ```

7. 部署：

   ```powershell
   npm run deploy
   ```

## 使用

- 第一次打开时先用主管理员邮箱注册，会创建主管理员保险箱。
- 注册默认关闭。主管理员登录后可以在“管理员设置”里开放或关闭新用户注册。
- 后续用同一个邮箱和密码登录。
- 可以直接分享你的站点地址。只有在主管理员开放注册后，其他人才能注册自己的账号。
- 主管理员也可以在“管理员设置”里生成 7 天有效的一次性邀请链接。
- 2FA 字段填写 Google Authenticator / Authy 导出的 TOTP secret 后，页面会显示当前 6 位验证码。
- 2FA 字段也可以粘贴 `otpauth://` URI，页面会自动提取 secret。
- 密码字段支持生成强密码、强度提示和重复密码提示。
- 底部操作栏可以导入/导出加密备份、修改主密码、设置自动锁定时间、关闭本地加密缓存。
- 页面会注册一个轻量 service worker 缓存静态壳；离线可打开页面，但只有本地加密缓存存在时才能读取保险箱。

## 内置限流

当前版本使用 Cloudflare KV 做基础固定窗口限流：

- 注册：每个 IP 每小时 5 次，每个邮箱每小时 3 次。
- 登录：每个 IP 每 15 分钟 30 次，每个邮箱每 15 分钟 10 次。
- 保险箱读取：每个用户每分钟 120 次。
- 保险箱写入：每个用户每分钟 60 次。
- 管理员设置：每个管理员每分钟 20 次。
- 主密码修改：每个用户每 15 分钟 5 次。

KV 限流不是强一致计数器，适合挡普通误用和低成本刷请求；如果公开给更多人使用，建议再加 Cloudflare Turnstile 或 Cloudflare WAF Rate Limiting。

## GitHub 发布建议

- 不要提交 `.dev.vars`、`.wrangler/`、Cloudflare API token、真实账号信息或导出的密文备份。
- 第一次公开前确认 `wrangler.toml` 里的 KV namespace id 是示例值或你愿意公开的配置。
- 如果你分享自己的部署链接，先确认注册开关状态，并提醒对方使用自己的邮箱和强密码。

## 开发校验

```powershell
cmd /c npm run check
```

该命令会做 Worker 和前端脚本语法检查，并运行 Node 内置测试。
