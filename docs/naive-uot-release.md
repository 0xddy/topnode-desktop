# Naive/UoT v2：构建、资格验证与系统验收

本文件描述代码的发布流程，不代表任何平台已经完成正式验收。
基线是 Windows 11、macOS 13+、Ubuntu 24.04 GNOME；每个平台的
x86_64/ARM64 必须分别验证。没有测试设备或签名资源时只能产出 candidate。

## 固定运行契约

- 面板为所有 Naive JSON 出站下发 `udp_over_tcp.enabled=true, version=2`。
- 客户端只保留和校验该字段。旧缓存缺失时提示刷新，不补写、不启动 TCP-only 模式。
- 应用 UDP 关闭时路由直连，保留 UoT 与 QUIC 字段；内部 DNS 的 detour 不变。
- HTTPS/QUIC、系统信任/自定义 CA 独立声明 `uot-v2`，没有传输或信任自动回退。
- 系统 HTTP/HTTPS 代理不接管所有应用 UDP。SOCKS5 UDP 通过仅证明内核能力，
  完整接管必须另测 TUN。

## 原生产物与报告

`config/sing-box-acp.lock` 是唯一核心版本来源。构建命令：

```text
python scripts/build-sing-box-acp.py --target TARGET --output BUILD --with-naive --require-native
```

Windows/Linux 使用 purego 并复制对应架构 Cronet；macOS 必须在 Xcode 环境中
使用 CGO，最低系统版本为 13，不使用 DLL/SO 存在性判断 macOS 能力。
`source.json` 记录版本、提交、架构、标签、依赖及 SHA-256。
验证脚本使用 `PATH` 上的 Go 生成回环测试证书。

```text
python scripts/verify-naive.py --core BUILD/core/sing-box-acp[.exe] --metadata BUILD/source.json --report BUILD/core/naive-validation.json --system-fixture PRIVATE_FIXTURE
```

测试执行 HTTPS/QUIC、私有 CA/显式自签、错误 CA/过期/SNI/密码的反例，
成功连接还执行空、小、1200 字节、8192 字节 UDP echo 和 UDP DNS。
`--system-fixture` 的格式以脚本 `verify_system_fixture` 为准，使用隔离节点、
系统可信证书和仅能从节点访问的目标。没有它时仍可测试回环链路，但报告
`capabilities` 为空；**不能由回环证书成功推断系统信任能力**。
报告必须由实际测试生成，不能复制旧产物报告或手工填写通过。

运行时会同时核验当前 core probe、锁文件版本/提交/架构、核心和 Cronet 哈希、
schema-2 报告及每项 TCP/UDP/DNS/信任/认证结果。更换产物会使旧报告失效。
候选包可以缺少完整报告；正式打包拒绝缺少对应证据的产物。

## Linux 安装

原生编译 `cargo build --release -p topnode-desktop -p topnode-net-helper --target TARGET`。
`scripts/package-deb.py` 接收 `--application`、`--support-build`、`--core-build`、
`--target`、`--version-name`、`--source-date-epoch`、`--output`，未验收时必须加
`--candidate`。它生成 root 所有的 `/usr/lib/topnode`、systemd 服务、polkit action
及桌面入口。归档仍保留，但完整 TUN 基线以 `.deb` 安装后测试为准。

GNOME 使用 GSettings 捕获全部代理字段，dconf 单次更新并回读；保留 PAC、
例外、HTTP/HTTPS/SOCKS 设置。非 GNOME 明确报告系统代理不可用。
特权服务只执行固定 core，检查路径权限/哈希/锁定提交；使用 Unix socket
peer credentials、调用进程路径和 start-time、polkit 绑定调用方。拒绝任意
执行路径、shell 命令、外部文件引用、公开控制端口和不允许的入站。
GUI 仍为普通用户。断开 IPC 会终止对应核心并等待清理；systemd 管理整个 cgroup。

升级/删除先向 GUI 发送 TERM，让其恢复用户代理；超时则拒绝替换仍运行的应用。
之后停止 helper。不要绕过安装脚本直接删除正在使用的安装目录。

## macOS 安装与签名

1. 原生构建 app/core，运行 `scripts/build-macos-support.py --target TARGET --output SUPPORT`。
2. 用 `scripts/sign-macos-inputs.py --application APP_EXE --core-build BUILD --support-build SUPPORT --identity IDENTITY`
   签名 core、GUI、代理工具、XPC bridge 和 daemon。此步骤会更新 core 元数据哈希；
   必须在原生资格测试之前执行，不能继续使用签名前的报告。
3. 运行上述原生资格测试。`package-portable.py` 使用 `--support-build` 和
   `--signing-identity` 签名外层 bundle，不使用 ad-hoc 或重新深度签名已验证的 core。
4. 解开生成归档，将完整 `.app` 交给 `scripts/package-macos.py --app APP --output INSTALLER.pkg
   --version VERSION_CODE --installer-identity IDENTITY --notary-profile KEYCHAIN_PROFILE`。
   凭据只通过已有 Keychain profile 使用，不写入仓库。脚本提交公证、staple、验证安装签名。
5. 安装到 `/Applications/TOPNODE Desktop.app`，首次 TUN 通过 SMAppService 注册，
   用户在系统设置批准后台服务。未批准时不报告已连接。

SystemConfiguration 按 network service ID 保存完整代理字典。新增服务补记租约，
退出只恢复仍属于本程序的服务，保留外部修改。SMAppService daemon 只接受同团队、
固定签名标识的 bridge；bridge 在发送配置前验证 root daemon 响应。核心另行验证
固定路径、root 所有权、哈希、锁定版本和同团队签名标识。

卸载：先退出应用并确认代理已恢复，用已签名 bridge 的 `unregister` 操作撤销
SMAppService，再删除 app。若 GUI 异常退出，先重新启动完成租约恢复；不要直接
删除 journal。系统设置里仍可撤销后台项目。签名、公证、安装、升级、卸载均需实机验收。

## 系统验收报告与正式发布

`package-portable.py` / `package-deb.py` 正式模式要求 `--system-acceptance REPORT`。
schema-1 报告绑定 `target`、`application_sha256`、`core_sha256`、`helpers`（文件名到哈希）。
`checks` 必须覆盖：system_proxy、tun_udp、udp_disabled、dns_detour、permission_denied、
process_exit_cleanup、external_proxy_change、network_switch、sleep_wake、upgrade、uninstall。
另需 `soak_seconds>=3600`、`mixed_traffic_seconds>=1800`、`connection_cycles>=100`；
macOS 需要 `notarized_install=true`。保留每项测试日志和系统状态证据，不手填虚假通过。

平台 API 依据：[Apple SMAppService](https://developer.apple.com/documentation/servicemanagement/smappservice)、
[XPC 签名要求](https://developer.apple.com/documentation/foundation/nsxpcconnection/setcodesigningrequirement(_:))、
[签名信息 API](https://developer.apple.com/documentation/security/seccodecopysigninginformation(_:_:_:))。

`.github/workflows/portable-release.yml` 只生成六目标候选包和原生证据，不自动
发布 GitHub/dufs，不更新线上 bootstrap。`publish-dufs.py` 拒绝 candidate/preview
及缺少 supported 标记的包。正式发布是单独操作：使用原始已验收产物重新打包，
检查全部报告和哈希后，按发布授权上传，再更新 bootstrap。
不应为了通过门禁手工修改 BUILD-INFO、核心 metadata 或验证报告。

## 必须补做的验收

- 六目标原生执行；macOS Swift/CGO/签名代码必须首先在 Xcode 编译。
- 干净系统真实系统代理/TUN、授权拒绝、helper 缺失/崩溃、GUI/sidecar 异常退出。
- 代理开关两态下的出口地址证明；QUIC/HY2 外层 UDP 与内部 DNS 不受应用开关误伤。
- IPv4/IPv6/域名、多目标 UDP、真正协商 HTTP/3 的应用目标，服务端限制与访问控制。
- 睡眠、换网、外部代理修改、新网络服务、普通用户安装升级卸载和重启恢复。
- 60 分钟稳定性、30 分钟混合流量、100 次重连与授权变更，RSS/线程/句柄/会话趋势。
- 回滚旧包时同样先清理 helper、代理、DNS、路由和特权 core；保留上一版完整产物。

系统验收与原生报告缺一不可，构建成功、单次网页成功均不能替代。
