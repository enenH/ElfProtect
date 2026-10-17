# ElfProtect

Android ARM64 ELF 保护工具，支持可执行文件和 JNI 动态库两种 loader。

当前默认打包格式为 **XZ-v1**：

`payload.so -> XZ(LZMA2, 4 MiB 字典, CRC64) -> RC4 -> trailer`

运行时加载格式为：

`读取 trailer -> RC4 解密 -> 内存解压 -> 校验 ARM64 ELF -> memfd -> android_dlopen_ext -> JNI_OnLoad`

新 loader 同时支持 XZ-v1 和旧版 ZIP 格式；`pack.py` 只生成 XZ-v1。旧 loader 无法读取 XZ-v1，必须使用同一版本的 loader、`pack.py` 和 `payload_format.py`。更早的“原始 ELF 直接 RC4”产物仍需重新打包。

项目生成两种 loader：

- `ElfProtect`：可执行文件入口，从 `/proc/self/exe` 读取自身 trailer。
- `libElfProtect.so`：JNI 动态库入口，导出 `JNI_OnLoad`，通过 `dladdr` 定位当前 `.so` 文件路径后读取自身 trailer。

## 格式

### XZ-v1

```text
[Loader ELF] [RC4(XZ ELF)] [RC4 Key: 32 B] [ELF Size: 8 B] [XZ Size: 8 B] [ELFXZ01\0: 8 B]
```

文件末尾的固定字段共 **56 字节**，两个大小字段均为小端 `uint64`：

| 相对 EOF 的偏移 | 大小 | 含义 |
| --- | --- | --- |
| `-8` | 8 字节 | Magic：`ELFXZ01\0` |
| `-16` | 8 字节 | 加密后的 XZ 数据大小 `size` |
| `-24` | 8 字节 | 解压后的 ELF 大小 |
| `-56` | 32 字节 | RC4 key |
| `-(56 + size)` | `size` 字节 | RC4 加密后的 XZ 字节流 |

XZ 数据必须是单个带 CRC64 校验的完整流，解压后长度必须与 trailer 一致，不接受尾随数据。打包器使用 LZMA2、压缩 preset 9 和 4 MiB 字典，运行时的字典上限也为 4 MiB。

### 旧版 ZIP

旧版格式保留 48 字节固定尾部，供兼容读取：

| 相对 EOF 的偏移 | 大小 | 含义 |
| --- | --- | --- |
| `-8` | 8 字节 | Magic：`ELFPROT\0` |
| `-16` | 8 字节 | 加密后的 ZIP 数据大小 `size`，小端 `uint64` |
| `-48` | 32 字节 | RC4 key |
| `-(48 + size)` | `size` 字节 | RC4 加密后的 ZIP 字节流 |

旧打包器生成的 ZIP 仅包含一个名为 `payload.so` 的文件。运行时继续通过仓库内的 `miniz` 解包。

格式常量、trailer 解析和 RC4 实现在 [PayloadFormat.h](PayloadFormat.h) 与 [payload_format.py](payload_format.py) 中维护；XZ 解码实现在 [PayloadXz.cpp](PayloadXz.cpp) 中。

## 运行时流程

可执行文件模式从 `/proc/self/exe` 读取 loader 文件；JNI `.so` 模式从当前 loader `.so` 路径读取文件。二者后续流程一致：

1. 检查文件大小并映射 loader 文件，打包文件最大为 1 GiB。
2. 根据尾部 magic 识别 XZ-v1 或旧 ZIP，校验大小字段和数据范围。
3. 复制加密数据并执行 RC4 解密，随后释放文件映射。
4. 使用 XZ Embedded 解码并校验 XZ；旧 ZIP 则通过 `miniz` 提取唯一的非目录、受支持 entry。
5. 检查解压后的 ELF 大小为 64 字节至 512 MiB，且 ELF 头标识为小端 ELF64、ARM64、`ET_DYN`。
6. 将 ELF 完整写入 `memfd`。
7. 通过 `android_dlopen_ext` + `ANDROID_DLEXT_USE_LIBRARY_FD` 从 `memfd` 加载。
8. 解析并调用 payload 的 `JNI_OnLoad`。

JNI `.so` 模式会把真实 `JavaVM*` 和 `reserved` 原样传给原始动态库的 `JNI_OnLoad`。成功后会保留原始动态库句柄，不主动 `dlclose`，避免已注册 native 方法指向被卸载代码。

可执行文件模式把 `argc` 和 `argv` 转为指针后传给 payload 的 `JNI_OnLoad`，不会创建 Java VM；payload 需要适配这一调用约定。调用结束后会卸载 payload。

加载过程中检查失败会返回 `JNI_ERR`（`-1`）；成功调用后返回 payload 的 `JNI_OnLoad` 结果。临时文件描述符、映射、解码器状态和堆内存会统一清理。

## 构建

要求：

- Android NDK 29+
- CMake 3.21+
- 支持 C++23 的编译器（使用 NDK Clang）
- Git；以下示例使用 Ninja 作为构建工具
- Python 3.11+，需包含标准库 `lzma`（用于打包，无需额外 pip 依赖）

CMake 通过 `FetchContent` 获取 XZ Embedded，固定到提交 `ae63ae3a36ed01724674e8f3d750dc47bf125410`。首次配置需要能够访问其 Git 仓库。

Linux/macOS：先将 `ANDROID_NDK_HOME` 指向本机 NDK 目录，再执行：

```bash
cmake -S . -B build -G Ninja \
  -DCMAKE_ANDROID_NDK="$ANDROID_NDK_HOME" \
  -DCMAKE_TOOLCHAIN_FILE="$ANDROID_NDK_HOME/build/cmake/android.toolchain.cmake" \
  -DANDROID_ABI=arm64-v8a \
  -DANDROID_PLATFORM=android-30 \
  -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
```

Windows PowerShell（按本机安装位置调整 `$ndk`）：

```powershell
$ndk = 'D:/Android/SDK/ndk/29.0.13113456'
cmake -S . -B build -G Ninja `
  "-DCMAKE_ANDROID_NDK=$ndk" `
  "-DCMAKE_TOOLCHAIN_FILE=$ndk/build/cmake/android.toolchain.cmake" `
  -DANDROID_ABI=arm64-v8a `
  -DANDROID_PLATFORM=android-30 `
  -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
```

未显式设置 `CMAKE_ANDROID_NDK` 时，`CMakeLists.txt` 使用其中预设的 Windows NDK 路径。当前实现面向 `arm64-v8a`，以上示例和 CI 均使用 Android API 30。

构建后会生成：

- `build/ElfProtect`（CMake target：`ElfProtect`）
- `build/libElfProtect.so`（CMake target：`ElfProtectJni`）

## 打包

将同版本的 `pack.py` 和 `payload_format.py` 放在同一目录，CLI 参数保持不变：

```bash
python pack.py <stub> <payload.so> <output>
python pack.py --help
```

可执行文件模式示例：

```bash
python pack.py build/ElfProtect original.so protected_output
```

JNI 动态库模式示例：

```bash
python pack.py build/libElfProtect.so original.so liboriginal.so
```

打包器会检查：

- stub 和 payload 的 ELF 头必须为小端 ELF64、ARM64；payload 必须为 `ET_DYN` 动态库。
- stub 必须包含 XZ-v1 能力标记 `ElfProtect:XZ1:LZMA2:4MiB:CRC64`，且没有已有的 XZ-v1 或 ZIP trailer。
- payload 大小为 64 字节至 512 MiB，最终打包文件不超过 1 GiB。
- 输出路径不能与 stub 或 payload 输入路径相同。

每次打包使用随机生成的 32 字节 RC4 key，并在写入前解密、解压，逐字节比对原始 payload。输出先写入同目录临时文件，再原子替换目标文件，最后重新读取并验证。父目录会自动创建，已有输出文件会被替换。

最终放进 APK 的是打包后的 `liboriginal.so`，文件名按应用实际 `System.loadLibrary` 名称决定。当前实现要求 loader `.so` 是普通已解压文件路径，不支持 `base.apk!/lib/...` 形式直接从 APK 内部读取 appended trailer。

输出日志会显示：

- `Stub size`
- `Payload size`
- `XZ size`（含 4 MiB 字典、CRC64 信息）
- `XZ ratio`（XZ 大小 / 原始 payload 大小）
- `Output size`
- `Output`

## CI 产物

[GitHub Actions](.github/workflows/build.yml) 使用 NDK r29 构建两个 loader，并通过 `AMICE_TOKEN` 下载 amice 混淆插件。上传的 `ElfProtect-arm64-v8a` artifact 包含以下配套文件：

- `ElfProtect`
- `libElfProtect.so`
- `pack.py`
- `payload_format.py`

默认分支（当前为 `main`）的 push 或手动构建成功后，还会自动创建或更新
[`latest` Release](https://github.com/enenH/ElfProtect/releases/tag/latest)，上传
`ElfProtect-arm64-v8a.tar.gz`，内容与该次 Actions artifact 一致，并保留 loader 的执行权限。
`latest` 标签会同步指向构建提交；重复运行会替换同名附件。Release 说明包含提交 SHA 和 Actions 运行链接。

PR 和其他分支的构建只上传 Actions artifact。发布作业使用内置 `GITHUB_TOKEN` 的
`contents: write` 权限，无需额外配置发布 token；下载 amice 仍需已有的 `AMICE_TOKEN`。
发布作业串行执行，并跳过已不再是默认分支最新提交的构建，避免旧产物覆盖新版本。

## 依赖

- [HideImport](https://github.com/nickchapo/HideImport)
- [obfusheader.h](https://github.com/ac3ss0r/obfusheader.h)
- [XZ Embedded](https://github.com/tukaani-project/xz-embedded)：XZ-v1 运行时解码，由 CMake 获取固定版本
- [miniz](https://github.com/richgel999/miniz)：兼容旧版 ZIP 格式

`miniz` 以仓库内 vendored 单体源码形式提供：

- [third_party/miniz/miniz.h](third_party/miniz/miniz.h)
- [third_party/miniz/miniz.c](third_party/miniz/miniz.c)
- [third_party/miniz/LICENSE](third_party/miniz/LICENSE)

XZ Embedded 编译时启用 `XZ_USE_CRC64`、`XZ_DEC_DYNALLOC` 和 `XZ_DEC_ARM64`。当前 Python 打包器仅使用 LZMA2 filter。

`miniz` 编译时启用：

- `MINIZ_NO_STDIO`
- `MINIZ_NO_TIME`
- `MINIZ_NO_ARCHIVE_WRITING_APIS`
