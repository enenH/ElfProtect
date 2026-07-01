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

set(MINIZ_SOURCE ${CMAKE_CURRENT_SOURCE_DIR}/third_party/miniz/miniz.c)
set(ELFPROTECT_SOURCES
        main.cpp
        ${MINIZ_SOURCE}
)

function(configure_elfprotect_target target_name)
    target_include_directories(${target_name} PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/third_party/miniz
    )

    target_compile_definitions(${target_name} PRIVATE
            MINIZ_NO_STDIO
            MINIZ_NO_TIME
            MINIZ_NO_ARCHIVE_WRITING_APIS
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
