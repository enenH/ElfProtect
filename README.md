# ElfProtect

Android ELF 保护工具。

当前打包格式为：

`payload.so -> ZIP(单文件 payload.so) -> RC4 -> trailer`

运行时加载格式为：

`读取 trailer -> RC4 解密 -> 内存 ZIP 解包 -> 校验 ELF -> memfd -> android_dlopen_ext`

不兼容旧的“原始 ELF 直接 RC4”产物，历史包需要重新打包。

## 格式

```
+------------------+------------------------+----------+----------+----------+
|   Loader Stub    | RC4 Encrypted ZIP Data | RC4 Key  |  Size    |  Magic   |
|   (ELF exec)     |                        | (32 B)   | (8 B)    | (8 B)    |
+------------------+------------------------+----------+----------+----------+
```

`trailer` 仍然位于文件末尾，固定字段布局不变：

| Offset from EOF | Size | Meaning |
| --- | --- | --- |
| `-8` | 8 bytes | Magic: `ELFPROT\0` |
| `-16` | 8 bytes | Encrypted payload size, little-endian `uint64` |
| `-48` | 32 bytes | RC4 key |
| `-(48 + size)` | `size` bytes | RC4 加密后的 ZIP 字节流 |

ZIP 归档固定只包含一个 entry，名称固定为 `payload.so`。

## 运行时流程

1. 读取 `/proc/self/exe` 并定位文件尾部 trailer。
2. 校验 magic，解析 RC4 key 和加密 payload 大小。
3. RC4 解密得到内存 ZIP 归档。
4. 使用 vendored `miniz` 在内存中打开 ZIP。
5. 要求 ZIP 内文件数必须为 1，且 entry 不是目录、不是不支持的格式。
6. 解包到堆内存后校验前 4 字节必须为 `0x7F 'E' 'L' 'F'`。
7. 将解包出的 ELF 写入 `memfd`。
8. 通过 `android_dlopen_ext` + `ANDROID_DLEXT_USE_LIBRARY_FD` 从 `memfd` 加载。
9. 解析并调用 `JNI_OnLoad`。

任一步骤失败都会返回 `-1`，并统一清理 `fd`、`mmap`、ZIP reader 状态和堆内存。

## 构建

要求：

- Android NDK 29+
- CMake 3.21+
- C++23
- Python 3.11+（`pack.py` 使用 `zipfile.ZipFile(..., compresslevel=9)`）

构建：

```bash
cmake -S . -B cmake-build-debug
cmake --build cmake-build-debug
```

## 打包

CLI 保持不变：

```bash
python pack.py <stub> <payload.so> <output>
```

示例：

```bash
python pack.py cmake-build-debug/ElfProtect original.so protected_output
```

输出日志会显示：

- `Stub size`
- `Payload size`
- `ZIP size`
- `ZIP ratio`
- `Output size`

## 依赖

- [HideImport](https://github.com/nickchapo/HideImport)
- [obfusheader.h](https://github.com/ac3ss0r/obfusheader.h)
- [miniz](https://github.com/richgel999/miniz)

`miniz` 以仓库内 vendored 单体源码形式提供：

- [third_party/miniz/miniz.h](third_party/miniz/miniz.h)
- [third_party/miniz/miniz.c](third_party/miniz/miniz.c)
- [third_party/miniz/LICENSE](third_party/miniz/LICENSE)

编译时启用：

- `MINIZ_NO_STDIO`
- `MINIZ_NO_TIME`
- `MINIZ_NO_ARCHIVE_WRITING_APIS`
