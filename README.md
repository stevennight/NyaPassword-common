# NyaPassword 公共库（common）

服务端（`../server`）、桌面端（`../desktop`）、浏览器扩展（`../chrome`）、Android（`../android`）共用的代码：Rust 核心（加密、数据模型、同步与合并、网址匹配、TOTP、passkey、SSH、导入导出、备份格式）、共享 Web 界面、自动填充词表与测试页。

状态：设计阶段，尚无代码。

- 设计方案：[docs/设计方案.md](docs/设计方案.md)
- 开发计划：[docs/开发计划.md](docs/开发计划.md)
- 界面原型：[docs/prototype.html](docs/prototype.html)（浏览器直接打开）

## 仓库布局

各仓库克隆到同一个父目录（产品仓库通过 `../common` 引用本仓库）：

```powershell
gh repo clone <owner>/NyaPassword-common  common
gh repo clone <owner>/NyaPassword-server  server
gh repo clone <owner>/NyaPassword-desktop desktop
gh repo clone <owner>/NyaPassword-chrome  chrome
gh repo clone <owner>/NyaPassword-android android
```

common 不单独发版；各产品仓库发版时用 `COMMON_REF` 固定所用的 common 提交。
