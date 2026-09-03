# StarKey Render

## 部署
1. 将本项目上传 GitHub。
2. 在 Render 创建 Web Service。
3. 使用 Node 环境。
4. Build Command: `npm install`
5. Start Command: `npm start`
6. 配置 `DATABASE_URL`（推荐 Render PostgreSQL）。
7. 配置 `ADMIN_PASSWORD`。不要把真实管理员密码写进 GitHub。
8. `ADMIN_TOKEN` 可由 Render 自动生成。

## API
POST `/api/key`
- username
- robloxUserId（可选）

POST `/api/verify`
- username
- key

POST `/api/admin/login`
- password

## 说明
普通网页无法可靠读取 Wi-Fi SSID，也无法保证永久不变的硬件设备 ID。
本项目使用服务器记录的 IP、浏览器信息哈希和 Roblox UserId 做绑定/封禁辅助。
VPN/代理检测需要额外的第三方 IP 情报服务；本基础版没有伪装成“100% VPN 检测”。

## Roblox
`roblox/KeyVerifier.client.lua` 是客户端示例。生产环境应让 Roblox 服务器通过 HttpService 调用自己的验证 API，并由服务器决定玩家是否通过。
