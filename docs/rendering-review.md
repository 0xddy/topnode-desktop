# 弹层与局部重绘检查

日期：2026-09-08。本次修改接续登录和窗口控件调整。

## 原因与修改

- 节点弹层上透出的绿色地球来自首页。当前 Slint 1.17.1 软件渲染器的 `RenderToBuffer::process_filled_path` / `process_stroked_path` 直接绘制路径，没有像矩形、纹理绘制一样限制到 dirty region。局部刷新时，路径可能改写本次刷新区域之外的像素，后续弹层绘制无法完全覆盖这些写入。
- 将现有的 36 个静态 `Path` 图标转换为 SVG 资源，通过 `Image` 绘制并使用 `colorize` 保留状态颜色。没有修改渲染依赖、切换 GPU 后端或通过持续全屏重绘掩盖问题。节点列表、页面、导航、按钮和登录复选框共用同一绘制方式。
- 节点弹层和较高的购买/支付弹层为自定义窗口控件预留顶部空间；遮罩仍覆盖整个窗口，窗口控件在遮罩上使用浅色，两个关闭按钮不再重叠。
- 国旗只绘制匹配图片或兜底图标之一，修复禁用节点中兜底地球透过半透明国旗的叠影。保留全部 249 个国旗映射；查找分为短函数，避免大段返回分支触发 Windows Slint 编译器栈溢出。

## 验证

新增桌面软件渲染回归测试，使用真实 `AppWindow` 与可控时钟，在多个节点行间移动指针，将复用缓冲区局部重绘的结果与相同状态下的完整重绘逐像素比较。修改前第一个位置有 81 个像素不一致，修改后全部测试位置一致。

通过原生窗口预览实测节点行悬停、滚动、关闭弹层，以及主页和个人中心的图标。节点弹层不再出现首页地球，禁用节点无兜底图标叠影，窗口按钮与弹层分开显示。预览使用本地样例数据，没有向生产服务提交测试登录或节点连接请求。

工作区测试共 212 项通过、1 项默认忽略。`cargo fmt --all --check`、`cargo clippy --workspace --all-targets -- -D warnings`、`cargo build -p topnode-desktop`、28 个 Slint 文件编译检查及 `git diff --check` 均通过。截图和验证日志保存在 `D:/Temp/topnode-ui-validation-20260908/`：

- `rendering-qa/before-node-modal.png`：复现的旧版残影。
- `rendering-qa/after-node-hover.png`：修复后的节点列表悬停。
- `render-before.log` / `render-after.log`：回归测试修改前失败、修改后通过的记录。
- `rendering-tests.log`：最终全量测试。
- `rendering-clippy.log` / `rendering-build.log`：静态检查与最终构建。

已将验证构建同步到 `target/debug/topnode-desktop.exe` 并重启程序；原程序备份在 `rendering-qa/topnode-desktop.before.exe`。最终 SHA-256：`9ff54b81573fa8bfd7a9d92e3f640002262f9a1397f78fd16bb72d0cfaa5c99d`。

前序流程和窗口外边框检查见 [`login-flow-review.md`](login-flow-review.md)。

## 2026-09-09：托盘恢复后出现大片空白

- 已在运行中的 Windows 客户端复现。隐藏窗口后，原生窗口的显示内容可能丢失，但软件渲染器保留的位图及其 buffer age 仍有效。Slint 1.17.1 的 winit 软件后端按 dirty region 调用 `present_with_damage`；仅调用 `request_redraw()` 不会恢复未发生变化的区域。
- 统一的 `restore_main_window` 在成功显示窗口后，将当前窗口的完整逻辑坐标区域标记为 dirty，再请求绘制。托盘点击、菜单显示和单实例唤醒都经过这一入口；后续绘制继续使用局部刷新。
- Slint 的公开窗口接口没有全区域失效方法，因此将 `WindowInner` / `mark_dirty_region` 的内部接口使用限制在平台层的一个辅助函数中。项目仍固定使用 Slint 1.17.1，升级时需要重新检查此兼容处理。
- 新增测试保留软件位图、清空模拟窗口画面，仅按实际返回的 damage 区域呈现，并与独立完整帧逐像素比较。覆盖 100%、125%、150% 缩放、首页与节点弹层、每种场景三轮隐藏恢复，以及绘制前连续两次恢复。另检查恢复后的空闲帧 damage 为空。修复前第一次恢复有 544,793 个像素不一致，修复后通过。
- 使用真实 winit 软件后端和相同平台代码的本地样例窗口，验证首页及节点弹层隐藏后连续恢复两次，画面完整；恢复后关闭弹层也正常。原生验证使用内存样例数据。

本次日志与原生截图位于 `D:/Temp/topnode-ui-validation-20260908/`，文件名前缀为 `tray-restore-`。临时原生验证程序源码保留在该目录，不进入产品构建。

工作区测试 215 项通过、1 项默认忽略；格式检查、Clippy（所有目标、警告视为错误）通过。本机可编译平台为 Windows x86_64；已安装的 ARM64 Windows 和 Linux Rust 标准库缺少对应 C/C++ 交叉工具链，未验证这两个平台。

`cargo build -p topnode-desktop` 通过，已将构建同步至 `target/debug/topnode-desktop.exe` 并重启。新版实际客户端隐藏到托盘后，通过单实例唤醒同一恢复入口，窗口标识保持不变且画面完整。旧程序备份为 `tray-restore-before.exe`，新程序 SHA-256 为 `2818d419ca3847c5f98cc7c1af733ef44412ac68ddc8c0d6f3eb2b0c5c5f2872`。
