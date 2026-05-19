# FileSigner - 批量文件签名工具

## 项目简介
FileSigner 是一个基于 C 语言和 OpenSSL 开发的批量文件签名工具，支持使用 CA 证书对目录中的文件进行数字签名和验证。

## 主要功能
- ✅ 批量文件数字签名
- ✅ 签名状态检测（避免重复签名）
- ✅ 多线程加速处理
- ✅ 签名验证功能
- ✅ 跨平台支持（Windows/Linux/macOS）

## 快速开始

## 深入了解

- [📖 时间戳安全性详解](./docs/timestamp-security.md) — 哈希碰撞、本地篡改攻击、TSA 信任模型等常见疑虑的深度解答

### 编译
```bash
# 使用 CMake
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
cmake --build .

# 或使用 Makefile（Linux/macOS）
make
```