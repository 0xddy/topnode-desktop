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
