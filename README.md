# ElfProtect

Android ELF 文件加固保护工具。将原始 `.so` 共享库加密后附加到加载器桩（stub）中，运行时在内存中解密并加载，无需落盘。

## 原理

```
+------------------+--------------------+----------+----------+----------+
|   Loader Stub    | RC4 Encrypted .so  | RC4 Key  |  Size    |  Magic   |
|   (ELF exec)     |                    | (32 bytes)| (8 bytes)| (8 bytes)|
+------------------+--------------------+----------+----------+----------+
```

**加载流程：**

1. 读取 `/proc/self/exe` 获取自身完整二进制
2. 从文件末尾解析 trailer：验证 magic `ELFPROT\0`，提取 payload 大小和 RC4 密钥
3. RC4 解密得到原始 `.so`
4. `memfd_create` 创建匿名内存文件描述符
5. 将解密后的 ELF 写入 memfd
6. 通过 `android_dlopen_ext` + `ANDROID_DLEXT_USE_LIBRARY_FD` 从 memfd 加载
7. `dlsym` 获取 `JNI_OnLoad` 函数并调用

## 保护特性

| 特性 | 说明 |
|------|------|
| 导入隐藏 | `dlsym` 通过 ELF 解析获取（HideImport），所有其他函数通过 dlsym 间接解析 |
| 字符串加密 | 所有字符串字面量使用 `OBF()` 编译期 XOR 加密 |
| 间接调用 | 所有外部函数通过运行时解析的函数指针调用，`rc4_crypt` 通过 `CALL()` 宏隐藏 |
| 控制流混淆 | `obfusheader.h` 注入虚假分支、间接跳转，干扰 IDA/Ghidra 反编译 |
| 内存加载 | 解密后的 `.so` 仅存在于内存中（memfd），不写入磁盘 |
| 随机密钥 | 每次打包生成 32 字节随机 RC4 密钥 |

## 项目结构

```
ElfProtect/
├── main.cpp           # 加载器桩 — 解密 + memfd 加载 + 调用 JNI_OnLoad
├── pack.py            # Python 打包脚本 — RC4 加密 + 拼接 trailer
├── HideImport.hpp     # ELF 符号解析库 — 通过 /proc/self/maps + ELF 解析隐藏导入
├── obfusheader.h      # 编译期混淆库 — OBF() 字符串加密 / CALL() 间接调用 / 控制流混淆
└── CMakeLists.txt     # Android NDK 构建配置
```

## 构建环境

- Android NDK 29+
- CMake 4.0+
- C++23
- Python 3.6+
- 目标架构：arm64-v8a（Android API 30）

## 使用方法

### 1. 构建加载器桩

```bash
cmake -B build \
  -DCMAKE_ANDROID_NDK=/path/to/ndk \
  -DCMAKE_TOOLCHAIN_FILE=/path/to/ndk/build/cmake/android.toolchain.cmake \
  -DCMAKE_SYSTEM_NAME=Android \
  -DCMAKE_ANDROID_ARCH_ABI=arm64-v8a \
  -DANDROID_PLATFORM=android-30

cmake --build build
```

### 2. 打包加固

```bash
python pack.py build/ElfProtect original.so protected_output
```

输出示例：
```
[+] Packed successfully:
    Stub size:    3417064 bytes
    Payload size: 5644720 bytes
    Output size:  9061832 bytes
    Output:       protected_output
```

### 3. 部署执行

```bash
adb push protected_output /data/local/tmp/
adb shell chmod +x /data/local/tmp/protected_output
adb shell /data/local/tmp/protected_output [args...]
```

`argc` 和 `argv` 会作为参数传递给 `JNI_OnLoad(void* argc, void* argv)`。

## Trailer 格式

从文件末尾读取，固定 48 字节元数据：

| 偏移（从末尾） | 大小 | 内容 |
|---------------|------|------|
| -8 | 8 bytes | Magic: `ELFPROT\0` |
| -16 | 8 bytes | Payload 大小（小端序 uint64） |
| -48 | 32 bytes | RC4 密钥 |
| -(48 + size) | size bytes | RC4 加密的 payload |

## 依赖

- [obfusheader.h](https://github.com/ac3ss0r/obfusheader.h) — 编译期 C/C++ 代码混淆
- [HideImport](https://github.com/nickchapo/HideImport) — ELF 符号隐藏与导入解析

## 许可证

仅供安全研究与学习用途。
