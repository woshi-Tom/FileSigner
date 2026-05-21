# FileSigner — 批量 Authenticode PE 签名工具

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE.txt)
[![Platform](https://img.shields.io/badge/platform-Windows%20|%20Linux%20|%20macOS-lightgrey)]()

## 目录

- [为什么需要 FileSigner？](#为什么需要-filesigner)
- [它能做什么](#它能做什么)
- [核心概念](#核心概念)
- [快速上手](#快速上手)
  - [1. 编译](#1-编译)
  - [2. 生成测试证书](#2-生成测试证书)
  - [3. 签名文件](#3-签名文件)
  - [4. 验证签名](#4-验证签名)
- [图形界面操作指南](#图形界面操作指南)
- [命令行参考](#命令行参考)
- [架构设计](#架构设计)
- [常见问题](#常见问题)
- [安全说明](#安全说明)

---

## 为什么需要 FileSigner？

### 解决的问题

Windows 可执行文件（`.exe`、`.dll`）的数字签名是软件发布中的关键环节。签名起到两个作用：

1. **身份认证** — 用户能确认文件来自你（而不是恶意篡改者）
2. **完整性保护** — 文件发布后被篡改，签名验证会失败

在实际开发中，开发者常遇到以下痛点：

| 痛点 | 说明 |
|---|---|
| **批量签名** | 发布时需要对数十上百个 PE 文件逐一签名，手动操作耗时且容易遗漏 |
| **签名状态检测** | 重复签名可能破坏已有签名，需要自动跳过已签名文件 |
| **时间戳** | 签名证书过期后签名仍要有效，必须附加 RFC 3161 时间戳 |
| **测试证书** | 开发/CI 环境中需要快速生成自签名证书链，无需购买商业证书 |
| **验证** | 发布前需要验证签名是否正确、证书链是否完整 |
| **跨平台** | 在 Linux/macOS 构建服务器上也需要签名能力 |

**FileSigner 正是为解决这些问题而设计。** 它不依赖 Windows SDK（`signtool.exe`），而是基于 OpenSSL 实现完整的 Authenticode 签名流程，同样一个可执行文件同时提供图形界面和命令行两种操作方式。

### 与其他方案对比

| | FileSigner | signtool (Windows SDK) | OpenSSL 裸写 |
|---|---|---|---|
| 批量签名 | ✅ 内置 | ⚠️ 需脚本包裹 | ❌ 需大量脚本 |
| GUI 界面 | ✅ 原生 Win32 | ❌ 无 | ❌ 无 |
| 证书生成 | ✅ 一键生成 | ❌ 需 MakeCert / PowerShell | ⚠️ 手动操作 |
| 时间戳 | ✅ 内置 6 个 TSA，一键测速 | ✅ 支持 | ⚠️ 手动处理 |
| 跨平台 | ✅ Windows/Linux/macOS | ❌ 仅 Windows | ✅ |
| 依赖 | OpenSSL 3.x | Windows SDK (~1GB) | OpenSSL |

---

## 它能做什么

- **🔏 对 PE 文件签 Authenticode 名** — 使用 PFX/P12 证书对 `.exe` 文件进行 Authenticode 数字签名
- **📦 批量签名** — 扫描指定目录下的所有 `.exe` 文件逐个签名，支持递归子目录
- **⏱ 附加 RFC 3161 时间戳** — 签名同时从时间戳服务器（TSA）获取时间戳令牌，确保证书过期后签名仍可信
- **🔎 签名状态检测** — 自动跳过已签名的文件，支持 `--force` 强制重新签名
- **🛡 签名验证** — 验证 PE 文件的 Authenticode 签名有效性
- **🔑 生成自签名证书链** — 一键生成自签名根 CA + 代码签名证书（PFX），方便开发测试
- **🖥 原生 Win32 GUI** — KDE Breeze 风格界面，支持 TSA 测速、进度显示、深色日志、关于/检查更新
- **⚙ 命令行模式** — 同样一个可执行文件，传参数即进入 CLI 模式，适合 CI/CD 集成
- **🌐 跨平台构建** — 支持 Windows（MSVC/MinGW）和 Linux/macOS（GCC/Clang）

---

## 核心概念

### Authenticode

Authenticode 是 Microsoft 制定的 PE 文件数字签名标准。它将 PKCS#7 SignedData 结构嵌入 PE 文件的 Certificate Table 数据目录中。验证时，系统提取签名、验证证书链，并校验文件哈希是否与签名中的哈希一致。

### 时间戳 (RFC 3161)

时间戳服务器（TSA）对"文件哈希 + 当前时间"进行签名，证明该文件在某个时间点之前就已存在。即使签名证书过期，只要时间戳令牌有效，签名仍然可信。

详见 [时间戳安全性详解](./docs/timestamp-security.md)。

### 证书体系

FileSigner 可生成两级证书链：

```
自签名根 CA (FileSigner_RootCA)
  └── 代码签名证书 (FileSigner_Signer) → 导出为 PFX
```

根 CA 安装到系统"受信任的根证书颁发机构"后，由它签发的签名证书即可被系统信任。

---

## 快速上手

### 1. 编译

#### 前置条件

- **OpenSSL 3.x**（1.x 已 EOL，存在已知 CVE）
- **CMake 3.10+**
- **C11 编译器**（MSVC 2019+ / GCC / Clang）

#### 使用 CMake

```bash
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
cmake --build .
```

#### 使用 Makefile（Linux/macOS）

```bash
make
```

#### Windows 使用 vcpkg

```bash
# 安装 OpenSSL
vcpkg install openssl

# 配置时指定工具链
cmake .. -DCMAKE_BUILD_TYPE=Release -DCMAKE_TOOLCHAIN_FILE=[vcpkg-root]/scripts/buildsystems/vcpkg.cmake
cmake --build .
```

编译产物为单个可执行文件 `filesigner`（Windows 上为 `filesigner.exe`）。

### 2. 生成测试证书

开发和 CI 环境中建议使用自签名证书，避免购买商业证书的成本。

```bash
# 一键生成根 CA + 代码签名证书
./filesigner gen-cert --out-dir ./mycerts

# 输出：
#   ./mycerts/FileSigner_RootCA.cer     ← 根 CA 证书（导入系统受信任根目录）
#   ./mycerts/FileSigner_RootCA.key     ← 根 CA 私钥
#   ./mycerts/FileSigner_Signer.cer     ← 代码签名证书
#   ./mycerts/FileSigner_Signer.key     ← 代码签名证书私钥
#   ./mycerts/FileSigner_Signer.pfx     ← PFX 包（签名时使用）
```

#### 自定义证书参数

```bash
./filesigner gen-cert \
  --out-dir ./mycerts \
  --ca-password "ca_secret" \
  --signer-password "my_pfx_pass" \
  --validity-days 365 \
  --signer-cn "My Company Ltd" \
  --signer-email "dev@mycompany.com"
```

#### 将根 CA 导入系统（Windows）

签名后需要让系统信任签名。双击 `FileSigner_RootCA.cer` → **安装证书** → **受信任的根证书颁发机构**。

### 3. 签名文件

#### 签名单个文件

```bash
./filesigner sign ./MyApp.exe --pfx ./mycerts/FileSigner_Signer.pfx
```

#### 签名并附加时间戳

```bash
./filesigner sign ./MyApp.exe \
  --pfx ./mycerts/FileSigner_Signer.pfx \
  --password "my_pfx_pass" \
  --timestamp http://timestamp.digicert.com
```

#### 批量签名整个目录

```bash
# 签名当前目录下所有 .exe
./filesigner sign ./build \
  --pfx ./mycerts/FileSigner_Signer.pfx \
  --recursive \
  --timestamp http://timestamp.digicert.com \
  --output ./signed
```

#### 强制重新签名

```bash
./filesigner sign ./MyApp.exe --pfx cert.pfx --force
```

### 4. 验证签名

```bash
# 简单验证（仅检查签名结构）
./filesigner verify ./signed/MyApp.exe

# 验证证书链（需指定 CA 证书）
./filesigner verify ./signed/MyApp.exe --ca ./mycerts/FileSigner_RootCA.cer
```

---

## 图形界面操作指南

双击运行 `filesigner.exe`（不带任何命令行参数）即启动原生 Win32 图形界面。

### 界面布局

窗口顶部为扁平按钮栏：**签名** | **生成证书** | **关于** | **检查更新**，采用 KDE Breeze 设计风格。点击按钮切换对应页面，日志区位于底部深色终端风格。

#### 签名页

<img width="812" height="756" alt="image" src="https://github.com/user-attachments/assets/ea0c7d64-1220-4ee5-b015-4a0c56b59a32" />


| 控件 | 说明 |
|---|---|
| **目标** | 要签名的文件或目录路径，点击"浏览"选择 |
| **PFX 证书文件** | 代码签名证书的 PFX/P12 文件 |
| **PFX 密码** | PFX 文件的保护密码（若无密码则留空） |
| **时间戳服务器** | 下拉选择内置 TSA 服务器，也可手动输入 URL；点击"测速"测试所有 TSA 的延迟 |
| **输出目录** | 可选，留空则覆盖原文件 |
| **包含子目录** | 勾选后递归扫描子目录中的 `.exe` |
| **强制重新签名** | 勾选后对已签名文件也重新签名 |
| **调试日志** | 勾选后输出详细的内部处理日志 |
| **开始签名** | 点击开始签名，进度条和日志区实时显示进度 |

**操作流程：**

1. 填写目标路径（文件或目录）
2. 选择 PFX 证书文件并输入密码
3. （可选）选择时间戳服务器并点击"测速"选择最快的
4. （可选）设置输出目录
5. 点击"开始签名"
6. 在日志区查看每个文件的签名结果（绿色=成功，红色=失败，灰色=跳过）

#### 生成证书页

<img width="809" height="757" alt="image" src="https://github.com/user-attachments/assets/cb6f5d87-bccd-4d7e-b2e5-6bb6de579e9a" />


| 控件 | 说明 |
|---|---|
| **输出目录** | 证书文件保存位置（默认 `./certs`） |
| **签名证书有效期** | 代码签名证书有效天数（默认 90） |
| **PFX 密码** | 签名时使用 PFX 需要输入的密码 |
| **签名者姓名** | 证书的 CN（Common Name，可选） |
| **签名者邮箱** | 证书的 SAN 扩展（可选） |
| **生成证书** | 点击生成根 CA + 代码签名证书 |

**操作流程：**

1. 选择输出目录
2. 设置有效期和 PFX 密码
3. （可选）填写签名者名称和邮箱
4. 点击"生成证书"
5. 成功后会弹出提示，告知如何导入根 CA

#### 关于与检查更新

点击按钮栏右侧的 **关于** 查看版本信息，**检查更新** 通过 GitHub Releases API 自动检测新版本。

---

## 命令行参考

### 全局语法

```bash
filesigner <命令> [目标] [选项...]
```

### 命令一览

| 命令 | 功能 |
|---|---|
| `sign` | 签名文件或目录 |
| `gen-cert` | 生成自签名证书 |
| `verify` | 验证签名 |
| `help` / `-h` / `--help` | 显示帮助信息 |

### sign 命令

```
filesigner sign <文件|目录> --pfx <pfx> [选项]

选项:
  --pfx <文件>         PFX/P12 证书文件（必需）
  --password <密码>    PFX 密码
  --timestamp <URL>    时间戳服务器 URL
  --output <目录>      输出目录（默认覆盖原文件）
  --force              强制重新签名已签名的文件
  --recursive          扫描子目录
```

### gen-cert 命令

```
filesigner gen-cert [选项]

选项:
  --out-dir <目录>         输出目录（默认 ./certs）
  --ca-password <密码>     CA 密钥密码
  --signer-password <密码> PFX 密码（默认 FileSigner）
  --validity-days <天数>   签名证书有效天数（默认 90）
  --signer-cn <名称>       签名者 CN（默认 FileSigner Code Signing）
  --signer-email <邮箱>    签名者邮箱（SAN 扩展）
```

### verify 命令

```
filesigner verify <文件> [--ca <证书>]

选项:
  --ca <文件>    CA 证书路径（用于证书链验证）
```

### 使用示例

```bash
# 开发环境完整流程
filesigner gen-cert --out-dir ./certs
filesigner sign ./build/MyApp.exe --pfx ./certs/FileSigner_Signer.pfx --timestamp http://timestamp.digicert.com
filesigner verify ./build/MyApp.exe --ca ./certs/FileSigner_RootCA.cer

# CI/CD 批量签名
filesigner sign ./dist --pfx $PFX_PATH --password $PFX_PW --timestamp $TS_URL --recursive --output ./signed

# 仅检查是否已签名
filesigner verify ./build/MyApp.exe && echo "✅ Already signed" || echo "❌ Not signed"
```

---

## 架构设计

```
filesigner.exe
  │
  ├── main.c                   ← 入口：检测是否有命令行参数，分流到 CLI 或 GUI
  │
  ├── cli.c                    ← CLI 模式：解析参数，调用核心模块
  │
  ├── gui/gui_main.c           ← GUI 模式：KDE Breeze 风格，扁平按钮栏切换页面
  │     ├── 签名页             → 调用 batch_sign / authenticode_sign
  │     └── 证书生成页         → 调用 cert_generate
  │
  ├── core/
  │   ├── pe_file.c            ← PE 文件解析：DOS/COFF/Optional Header、Certificate Table
  │   ├── authenticode.c       ← Authenticode 签名 + 验证核心逻辑
  │   ├── cert_gen.c           ← 自签名根 CA + 代码签名证书生成
  │   ├── timestamp.c          ← RFC 3161 时间戳：DER 构造、HTTP 请求、令牌解析
  │   └── batch_signer.c       ← 批量签名：目录扫描、文件遍历、进度回调
  │
  ├── utils/
  │   └── file_utils.c         ← 文件操作：路径处理、UTF-8 支持、目录遍历
  │
  └── include/                 ← 头文件定义
```

### 设计特点

- **双模式入口**：同一个可执行文件，不带参数 → 启动 GUI；带参数 → 进入 CLI 模式（`main.c`）
- **非阻塞 GUI**：签名、证书生成、TSA 测速均在独立线程中执行，UI 保持响应（`gui_main.c`：`CreateThread`）
- **进度回调机制**：`batch_progress_cb` 和 `authenticode_status_cb` 两层回调，让 GUI 实时更新进度和日志
- **内存映射 PE 编辑**：`pe_file.c` 直接在内存中操作 PE 结构，避免临时文件
- **纯 OpenSSL 实现**：不依赖 Windows SDK，跨平台构建成为可能

### 依赖

- **OpenSSL 3.0+** — 加密运算、证书操作、PKCS#7/PKCS#12 处理
- **Windows 特定**（仅 GUI 运行时）：`winhttp`（HTTP 请求/更新检查）、`crypt32`（证书存储）、`comctl32`、`shell32`、`dwmapi`

---

## 常见问题

### Q: 为什么要用 OpenSSL 3.x，不能用 1.x 吗？

OpenSSL 1.x 已于 2023 年 9 月终止支持（EOL），不再接收安全补丁。使用 OpenSSL 3.x 可确保已知 CVE 已修复，同时获得 FIPS 140-3 合规支持。

### Q: 没有 PFX 证书怎么办？

使用 `gen-cert` 命令生成自签名证书链用于开发和测试。生产环境建议购买受信任的 CA 签发的代码签名证书（如 DigiCert、Sectigo 等）。

### Q: 时间戳必须吗？

不必须，但**强烈建议添加**。不带时间戳的签名在签名证书过期后验证会失败。带时间戳的签名可以永久有效（只要时间戳令牌本身有效）。

### Q: 签名后文件变大了，正常吗？

正常。签名会向 PE 文件的 Certificate Table 中嵌入 PKCS#7 SignedData，通常会增加几千字节（取决于证书链和时间戳令牌的大小）。

### Q: 能在 Linux/macOS 上签名 Windows 可执行文件吗？

可以。FileSigner 的签名逻辑（Authenticode）是纯 OpenSSL 实现的，不依赖 Windows API。Linux/macOS 上编译的版本可以签名 PE 文件——只需将 PFX 证书和目标 PE 文件放在同一台机器上即可。

### Q: 如何验证签名在 Windows 上被信任？

在资源管理器中右键点击已签名的 `.exe` → **属性** → **数字签名** 标签页，查看签名详情。如果使用自签名证书，需要先将根 CA 导入"受信任的根证书颁发机构"。

### Q: 签名后的文件能通过 Windows 的 WinVerifyTrust 验证吗？

可以。FileSigner 生成的 Authenticode 签名遵循 Microsoft 的 Authenticode PE Specification，Windows 的 `WinVerifyTrust` 函数可以正常验证。

---

## 安全说明

### 生产环境的证书管理

- **私钥保护**：生产环境的代码签名私钥应存储在 HSM（硬件安全模块）或硬件令牌中，不要直接保存在构建服务器文件系统中
- **CI/CD 集成**：在 CI 中使用时，通过 CI 平台的 Secrets 管理传递 PFX 密码，避免密码出现在日志或环境变量中
- **证书有效期**：代码签名证书通常有效期为 1-3 年。使用时间戳可以保证证书过期后的签名仍有效，但建议在证书到期前续期
- **根 CA 安装**：自签名根 CA 只应用于开发测试环境。生产环境应使用公共受信任的 CA

### 时间戳安全

时间戳是 Authenticode 安全模型中关键的一环。FileSigner 内置了 6 个公共 TSA 服务器，并提供了测速功能。关于时间戳安全的详细讨论（哈希碰撞、本地篡改攻击、TSA 信任模型等），请参阅：

[📖 时间戳安全性详解 →](./docs/timestamp-security.md)

---

## 许可证

本项目基于 [MIT 许可证](LICENSE.txt) 开源。

---

*FileSigner — 让 PE 签名不再是一件麻烦事。*
