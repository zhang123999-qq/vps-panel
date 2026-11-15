# 第三方组件与许可证

## 许可范围

本仓库自有代码（`cmd/`、`internal/`、`scripts/`、文档）以 **MIT** 发布，见 [`LICENSE`](LICENSE)。

**内嵌的内核二进制不在 MIT 范围内**，它们各自保留原有许可证（见下），
不因本项目的 MIT 许可而改变。

## 一、内嵌的内核二进制

| 组件 | 版本 | 位置 | 许可证 | 上游 |
|---|---|---|---|---|
| Xray-core | 26.11.9 | `internal/assets/kernels/xray/amd64/xray.gz` | **MPL-2.0** | https://github.com/XTLS/Xray-core |
| sing-box | 1.14.4 | `internal/assets/kernels/singbox/amd64/sing-box.gz` | **GPL-3.0** | https://github.com/SagerNet/sing-box |

这两个二进制由 `scripts/update-kernels.sh` 从上游官方 Release 下载、校验后内嵌，**未做任何修改**（未 patch、未重新链接）。

### 分发时的义务（重要）

- **自用不涉及分发**：仅自己编译、自己部署到自己的 VPS，不触发任何分发义务。
- **对外分发含 sing-box 的 exe**：sing-box 为 **GPL-3.0**，你需要在分发时满足 GPLv3 的相应义务
  （提供对应源码或**书面要约**，且不得对接收者附加额外限制）。
  本项目代码本身仍是 MIT，但其与 GPL 组件打包在同一可执行文件中，属于需要谨慎处理的情形。
- **只想避免 GPL 牵连**：两种做法
  1. 只内嵌 **Xray-core（MPL-2.0）**，不内嵌 sing-box（Hysteria2 / MASQUE 不可用）；
  2. 把本项目整体改为 **GPL-3.0**，与 sing-box 保持一致。
- MPL-2.0 是**文件级**弱著佐权：分发 Xray 二进制时需保留其许可证与版权声明，并对其**源文件**的修改开源；
  本项目未修改 Xray 源码，仅原样分发。

## 二、Go 依赖（编译进 exe）

| 模块 | 许可证 |
|---|---|
| github.com/gin-gonic/gin | MIT |
| gorm.io/gorm | MIT |
| github.com/glebarez/sqlite | MIT |
| modernc.org/sqlite（间接） | BSD-3-Clause |
| golang.org/x/crypto | BSD-3-Clause |

全部为宽松许可证，且均已通过 `CGO_ENABLED=0` 静态编译进单个 exe，无需附加动态库。

## 三、其它

- 前端为手写单页 HTML/CSS/JS，未引入第三方前端框架或 CDN 资源；
- 项目 logo / 图标：无（未使用第三方素材）；
- 文档中引用的命令与配置示例均为本项目原创。

---

如需重新生成上述清单：

```bash
go list -m -json all | jq -r 'select(.Replace == null) | "\(.Path) \(.Version)"'
```
