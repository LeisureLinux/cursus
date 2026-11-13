# cursus

**cursus** 是一个基于 [Talaria](https://github.com/X-VPN/Talaria) 协议库构建的VPN 服务端和客户端：
**一个二进制、两种角色**，根据命令行 `-role server|client` 区分。

- 协议：`TalariaUDP`（UDP/443）/ `TalariaTCP`（TCP/443）
- TLS：TLS 1.3，需部署证书
  **不允许跳过验证**
- 配置：单一 YAML 文件，两端字段一致
- 底层：Talaria 负责加密数据通道（外层 wire secret 封装、Retry、AEAD、
  会话授权、转发策略）；cursus 只负责进程生命周期、证书加载、TUN、
  路由/NAT、本地代理

> UDP 和 TCP 都统一使用端口 443（两者端口空间独立），防火墙一条规则即可覆盖。


## 单二进制

```
cursus -version
cursus -print-config -role server > cursus.yaml
cursus -role server -config cursus.yaml
cursus -role client -config cursus.yaml
cursus server -config cursus.yaml     # 子命令别名
cursus client -config cursus.yaml     # 子命令别名
```

`-role` 或子命令决定角色，YAML 里的 `mode` 必须一致（`Validate` 会检查）。
`-firewall` 打印要开的端口，`-duration 30s` 自动退出，`Ctrl-C` 优雅关闭。

## 服务端：一个进程同时提供 TCP 和 UDP

`cursus -role server` 在**同一个进程**里启动两个 Talaria listener：

| 协议 | 监听 | VIP 池 | TUN |
|---|---|---|---|
| `TalariaUDP` | UDP/443 | `10.77.0.0/24` | `cursus-s0` |
| `TalariaTCP` | TCP/443 | `10.78.0.0/24` | `cursus-t0` |

两者共享证书、静态账号、`wire_secret` 和目标策略；VIP 池与 nft 表按 TUN 名
隔离，避免回包路由冲突。只需要一个 systemd unit `cursus-server`。

```sh
cursus -role server -config configs/cursus-server.yaml -firewall
# UDP/443 + TCP/443
```

客户端二选一：`protocol: TalariaUDP` 或 `protocol: TalariaTCP`。

## 客户端两种接入方式

### 1) TUN 模式（三层 VPN，默认）

客户端建虚拟网卡，需要 root / `CAP_NET_ADMIN`。局域网设备把**默认网关指向
客户端机器**（或 DHCP 下发），所有 TCP/UDP/ICMP 自然进隧道。不需要任何代理。

```yaml
protocol: TalariaUDP          # 或 TalariaTCP
client:
  proxy:
    enabled: false
tun:
  mode: tun
```

### 2) 本地代理模式

客户端监听 `0.0.0.0:1080`（SOCKS5）和 `0.0.0.0:8080`（HTTP），
局域网设备在浏览器/应用里把代理指向客户端机器 IP 即可经服务端出网，
**不需要改默认网关、不需要每台设备装客户端、不需要 root**。

```yaml
protocol: TalariaTCP          # 代理模式要求 TCP
client:
  proxy:
    enabled: true
    listen_host: 0.0.0.0
    socks5_port: 1080
    http_port: 8080
tun:
  mode: echo                  # 代理模式不建 TUN
```

```sh
cursus -role client -config configs/cursus-client-proxy.yaml

# 局域网任意设备：
curl -x http://<client-lan-ip>:8080 https://example.com
curl --socks5-hostname <client-lan-ip>:1080 https://example.com
```

原理：每个代理连接映射成一条 TalariaTCP 的 `DialStream`（SOCKS5 CONNECT 流），
服务端做目标策略检查并拨号出网。HTTP 代理支持普通请求与 `CONNECT` 隧道。
这是应用层接入，只覆盖支持代理配置的应用；TUN 模式才是全流量三层接入。

> 代理模式必须使用 `TalariaTCP`；`Validate` 会拒绝 `TalariaUDP + proxy.enabled`。

## 配置

| 配置 | 角色 / 模式 |
|---|---|
| `configs/cursus-server.yaml` | server（单进程双协议） |
| `configs/cursus-client.yaml` | client / TalariaUDP + TUN |
| `configs/cursus-client-tcp.yaml` | client / TalariaTCP + TUN |
| `configs/cursus-client-proxy.yaml` | client / TalariaTCP + 本地 HTTP/SOCKS5 代理 |
| `configs/echo-local.yaml` | 免 root 回环自检 |

**部署前必须修改的占位符：**

| 字段 | 说明 |
|---|---|
| `identity` | 与证书 SNI 一致、两端相同、每个端点唯一 |
| `wire_secret` | ≥32 字节部署级密钥，两端相同 |
| `server.cert_file` / `key_file` | 自己的证书链与私钥路径 |
| `client.server_ip` | 自己的服务器公网 IP |
| `server.auth.*` / `client.client_id` / `secret_key` | 自己的凭据 |
| `client.proxy.listen_host` | 若要给局域网用，保持 `0.0.0.0` |

客户端**不需要任何证书文件**，用系统信任库 + SNI 校验；SNI 不能写成裸 IP。

## 构建与测试

```sh
make build          # -> bin/cursus（唯一二进制）
make test           # 单元 + race + 双协议端到端
make release        # linux amd64/arm64 + windows amd64 静态二进制
```

Go 静态链接（`CGO_ENABLED=0`），无运行时依赖。Linux/macOS/Windows 均可编译；
真实 TUN 转发仅 Linux，其它平台可用 `tun.mode: echo` 或代理模式。

> MTU 默认 **1314**（Talaria 对 UDP carrier 的上限：`1460-48-21-77`），
> 改大不会提速，只会让大包被丢弃。代理模式不涉及 MTU。

## 安装（Linux .deb）

CI 发布 `cursus_<version>_amd64.deb` / `_arm64.deb`（含 `/usr/bin/cursus`、
`/etc/cursus/*.yaml`、systemd units）和
`cursus-<version>-linux-{amd64,arm64}.tar.zst`（单静态二进制压缩包）。

```sh
sudo dpkg -i cursus_<version>_amd64.deb
sudo vi /etc/cursus/cursus-server.yaml       # 替换所有占位符
sudo systemctl enable --now cursus-server
sudo ss -lntup | grep ':443\b'
```

## 安装（Windows setup.exe）

CI 发布 `cursus-<version>-setup.exe`（NSIS）：装到
`C:\Program Files\cursus\`，包含 `cursus.exe` 和 YAML 配置。

```
cursus.exe -role client -config "C:\Program Files\cursus\config\cursus-client-proxy.yaml"
```

Windows 无真实 TUN provider，请使用代理模式。

## 发布流程（全部在 CI）

```
git tag v0.1.1 && git push origin v0.1.1
      ├─ build      : go test / vet / 静态交叉编译 + Linux tar.zst
      ├─ deb        : dpkg-deb 打 amd64 + arm64 两个 .deb
      ├─ windows    : makensis 打 setup.exe（唯一 Windows 发布物）
      └─ publish    : GitHub Release + SHA256SUMS
```

workflow：`.github/workflows/release.yml`。本地只改代码、打 tag、push。

## 目录

```
cmd/cursus/              单一 main，-role / 子命令区分角色
internal/config/          YAML schema + 校验
internal/app/             server/client 组装、证书、TUN、路由、本地代理
configs/                  示例 YAML
deploy/                   systemd units
packaging/deb/            dpkg-deb control 模板
packaging/windows/        NSIS setup.nsi
.github/workflows/        CI 静态编译 + 打包 + Release
scripts/                  安装参考、防火墙提示、压测脚本
third_party/talaria/      Talaria 上游源码快照（含 LICENSE、go.mod）
```

## 限制

- 示例 `wire_secret` 与凭据仅用于测试，部署前必须替换。
- `TunDevice.ReleaseVirtualIP` 在原型里没有 flush conntrack；生产需补。
- 代理模式只支持 TCP（SOCKS5 CONNECT / HTTP CONNECT + 普通 HTTP），
  不支持 UDP 代理；需要 UDP 全流量请用 TUN 模式。
- 不实现 DNS 下发、断线重连、多用户配额、按用户防火墙。
- 上游 Talaria 为 AGPL-3.0-only，快照保留在 `third_party/talaria/LICENSE`。

## 许可

**AGPL-3.0-only**。见 `LICENSE` 与 `NOTICE`。
