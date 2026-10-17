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
    set(ANDROID_STUDIO_BUILD true)
endif ()
project(ElfProtect)

set(CMAKE_CXX_STANDARD 23)

include(FetchContent)
FetchContent_Declare(elfprotect_xz
        GIT_REPOSITORY https://github.com/tukaani-project/xz-embedded.git
        GIT_TAG ae63ae3a36ed01724674e8f3d750dc47bf125410
)
FetchContent_MakeAvailable(elfprotect_xz)

set(MINIZ_SOURCE ${CMAKE_CURRENT_SOURCE_DIR}/third_party/miniz/miniz.c)
set(ELFPROTECT_SOURCES
        main.cpp
        PayloadXz.cpp
        ${MINIZ_SOURCE}
        ${elfprotect_xz_SOURCE_DIR}/linux/lib/xz/xz_crc32.c
        ${elfprotect_xz_SOURCE_DIR}/linux/lib/xz/xz_crc64.c
        ${elfprotect_xz_SOURCE_DIR}/linux/lib/xz/xz_dec_lzma2.c
        ${elfprotect_xz_SOURCE_DIR}/linux/lib/xz/xz_dec_stream.c
        ${elfprotect_xz_SOURCE_DIR}/linux/lib/xz/xz_dec_bcj.c
)

function(configure_elfprotect_target target_name)
    target_include_directories(${target_name} PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/third_party/miniz
            ${elfprotect_xz_SOURCE_DIR}/linux/include/linux
            ${elfprotect_xz_SOURCE_DIR}/userspace
    )

    target_compile_definitions(${target_name} PRIVATE
            MINIZ_NO_STDIO
            MINIZ_NO_TIME
            MINIZ_NO_ARCHIVE_WRITING_APIS
            XZ_USE_CRC64
            XZ_DEC_DYNALLOC
            XZ_DEC_ARM64
    )

    target_compile_options(${target_name} PRIVATE
            -Oz
            -fvisibility=hidden
            -fvisibility-inlines-hidden
            -fno-unwind-tables
            -fno-asynchronous-unwind-tables
            -fno-stack-protector
            -fomit-frame-pointer
            -DNDEBUG
    )

    target_link_options(${target_name} PRIVATE
            -Wl,--gc-sections
            -Wl,--icf=all
            -Wl,--strip-all
            -Wl,--exclude-libs,ALL
            -Wl,-z,norelro
            -static-libstdc++
    )
endfunction()

add_executable(ElfProtect
        ${ELFPROTECT_SOURCES}
)
configure_elfprotect_target(ElfProtect)
target_compile_definitions(ElfProtect PRIVATE
        ELFPROTECT_BUILD_EXECUTABLE
)

add_library(ElfProtectJni SHARED
        ${ELFPROTECT_SOURCES}
)
set_target_properties(ElfProtectJni PROPERTIES
        OUTPUT_NAME ElfProtect
)
configure_elfprotect_target(ElfProtectJni)
target_compile_definitions(ElfProtectJni PRIVATE
        ELFPROTECT_BUILD_SHARED
)
