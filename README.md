# <img src="https://github.com/tiagozip/cap/blob/main/docs/public/logo-small.webp?raw=true" alt="" align="left" width="40" height="40"> Cap

## 这是一个Cap的第三方版本 支持在Cloudflare worker上部署Cap人机验证

部署步骤：

1.克隆本项目置你的账户

2.在Cloudflare里面创建新应用并选择刚刚FROK的仓库

3.连接D1数据库 变量名**DB**

4.第一次部署后还不能用 在仪表盘里面设置环境变量ADMIN_KEY 这是登录密钥 理论是需要大于12个字符的

5.重新部署

TIP: Cloudlfare自带的域名在某些地区无法访问 建议配置自定义域名

