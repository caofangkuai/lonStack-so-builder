# lonStack-so-builder

通过 GitHub Action 自动从 boot.img 构建 preload.so

[![从 boot.img 构建 preload.so](https://github.com/caofangkuai/lonStack-so-builder/actions/workflows/build.yaml/badge.svg?branch=main)](https://github.com/caofangkuai/lonStack-so-builder/actions/workflows/build.yaml)

## 功能说明

自动从 boot.img 提取并生成 preload.so 文件，适用于 Android 系统的内核模块注入场景。

## 使用步骤

### 1. Fork 本仓库
点击右上角 **Fork** 按钮，将本仓库复制到你的 GitHub 账号下。

### 2. 准备 boot.img
获取你需要处理的 boot.img 文件（通常从设备固件或 ROM 中提取）。

### 3. 创建 Release
- 进入你 Fork 后的仓库页面
- 点击右侧 **Releases** 
- 点击 **Create a new release**
- 在 **Tag version** 中输入 `upload`
- 在 **Release title** 中输入任意标题（如 `Upload boot.img`）
- 上传你的 `boot.img` 文件到 Release 附件中
- 点击 **Publish release**

### 4. 触发 Action
- 进入仓库的 **Actions** 选项卡
- 选择 **从 boot.img 构建 preload.so** workflow
- 点击 **Run workflow** 下拉菜单
- 选择分支（通常为 `main`）
- 点击 **Run workflow** 按钮

### 5. 下载产物
- 等待 workflow 运行完成
- 点击运行记录进入详情页
- 在页面底部找到 **Artifacts** 区域
- 下载生成的 `preload.so` 文件

### 6. 执行提权
- 方法一 [https://rootme.wssllhdg.dpdns.org/lonStack/CVE-2026-43499/](https://rootme.wssllhdg.dpdns.org/lonStack/CVE-2026-43499/)
- 方法二 adb shell执行`cp 你下载的preload.so路径 /data/local/tmp/ && chmod +x /data/local/tmp/preload.so && LD_PRELOAD=/data/local/tmp/preload.so ~`

## 注意事项

- ⚠️ **仅支持无需修补偏移的 boot.img**
- 如果 boot.img 需要偏移修补，此工具无法正常处理，请使用其他工具链
- 确保上传的 boot.img 文件命名为 `boot.img`（大小写敏感）

## 工作原理

1. 监听 Release 创建事件（tag 为 `upload`）
2. 从 Release 附件中下载 `boot.img`
3. 执行提取和编译流程
4. 生成 `preload.so` 文件
5. 上传为 workflow artifact 供下载

## 常见问题

**Q: 如何获取 boot.img？**  
A: 可以从设备固件包中提取，或使用 `dd` 命令从设备分区备份。

**Q: 构建失败怎么办？**  
A: 检查 boot.img 是否完整且格式正确，确保其为无需偏移修补的版本。

---

如有问题，请提交 Issue 或 Pull Request。