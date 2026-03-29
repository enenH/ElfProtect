cmake_minimum_required(VERSION 3.21)
if (NOT DEFINED CMAKE_ANDROID_NDK)
    set(CMAKE_ANDROID_NDK D:/Android/SDK/ndk/29.0.13113456)
    set(CMAKE_TOOLCHAIN_FILE ${CMAKE_ANDROID_NDK}/build/cmake/android.toolchain.cmake)
    set(CMAKE_SYSTEM_NAME Android)
    set(CMAKE_SYSTEM_VERSION 24)
    set(CMAKE_ANDROID_ARCH_ABI arm64-v8a)
    set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
    set(ANDROID_ABI arm64-v8a)
    set(ANDROID_PLATFORM android-30)
    set(ANDROID_NDK ${CMAKE_ANDROID_NDK})
else ()
    SET(ANDROID_STUDIO_BUILD true)
endif ()
project(ElfProtect)

set(CMAKE_CXX_STANDARD 23)

add_executable(ElfProtect main.cpp)

target_compile_options(ElfProtect PRIVATE
        -Oz
        -fvisibility=hidden
        -fvisibility-inlines-hidden
        -fno-unwind-tables
        -fno-asynchronous-unwind-tables
        -fno-stack-protector
        -fomit-frame-pointer
        -DNDEBUG
)

target_link_options(ElfProtect PRIVATE
        -Wl,--gc-sections
        -Wl,--icf=all
        -Wl,--strip-all
        -Wl,--exclude-libs,ALL
        -Wl,-z,norelro
        -static-libstdc++
)
