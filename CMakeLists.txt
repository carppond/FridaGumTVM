cmake_minimum_required(VERSION 3.20)

# iOS toolchain 设置（必须在 project() 之前）
if(NOT DEFINED CMAKE_SYSTEM_NAME OR CMAKE_SYSTEM_NAME STREQUAL "iOS")
    set(CMAKE_SYSTEM_NAME iOS CACHE STRING "" FORCE)
    set(CMAKE_OSX_ARCHITECTURES "arm64" CACHE STRING "" FORCE)
    if(NOT DEFINED CMAKE_OSX_DEPLOYMENT_TARGET)
        set(CMAKE_OSX_DEPLOYMENT_TARGET "14.0" CACHE STRING "" FORCE)
    endif()
endif()

# Release 优化
set(CMAKE_C_FLAGS_RELEASE   "-O3 -flto -funroll-loops -fomit-frame-pointer -DNDEBUG" CACHE STRING "" FORCE)
set(CMAKE_CXX_FLAGS_RELEASE "-O3 -flto -funroll-loops -fomit-frame-pointer -DNDEBUG -fvisibility=hidden -fvisibility-inlines-hidden" CACHE STRING "" FORCE)

project(gumTVM LANGUAGES C CXX OBJCXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ==================== frida-gum devkit ====================
# 用户需要将 frida-gum-devkit-*-ios-arm64.tar.xz 解压到 prebuild/ios-arm64/
set(FRIDA_GUM_DIR "${CMAKE_CURRENT_LIST_DIR}/prebuild/ios-arm64")

# 查找 devkit 文件
if(EXISTS "${FRIDA_GUM_DIR}/libfrida-gum.a")
    set(FRIDA_GUM_LIB "${FRIDA_GUM_DIR}/libfrida-gum.a")
    set(FRIDA_GUM_INCLUDE "${FRIDA_GUM_DIR}")
    message(STATUS "Found frida-gum devkit at: ${FRIDA_GUM_DIR}")
else()
    message(FATAL_ERROR
        "frida-gum devkit not found!\n"
        "Please download frida-gum-devkit-*-ios-arm64.tar.xz from:\n"
        "  https://github.com/frida/frida/releases\n"
        "And extract it to: ${FRIDA_GUM_DIR}/\n"
        "Expected files: libfrida-gum.a, frida-gum.h"
    )
endif()

# ==================== 源文件 ====================
set(CORE_SOURCES
    core/gum_init.cpp
    core/entry.cpp
    core/instruction_tracer_manager.cpp
    core/instruction_callback.cpp
    core/custom_hook.cpp
    core/logger_manager.cpp
    core/hex_dump.cpp
    core/macho_utils.cpp
    core/objc_utils.mm
)

set(CORE_HEADERS
    core/common.h
    core/gum_init.h
    core/entry.h
    core/instruction_tracer_manager.h
    core/instruction_callback.h
    core/custom_hook.h
    core/logger_manager.h
    core/hex_dump.h
    core/macho_utils.h
    core/objc_utils.h
)

# ==================== 构建动态库 ====================
add_library(gumTVM SHARED ${CORE_SOURCES} ${CORE_HEADERS})

target_include_directories(gumTVM PRIVATE
    ${FRIDA_GUM_INCLUDE}
    ${CMAKE_CURRENT_LIST_DIR}/core
)

# 链接 frida-gum 静态库和系统框架
target_link_libraries(gumTVM PRIVATE
    ${FRIDA_GUM_LIB}
    "-framework Foundation"
    "-framework CoreFoundation"
    "-lresolv"
    "-ldl"
    "-lpthread"
)

# 导出符号
set_target_properties(gumTVM PROPERTIES
    # dylib 输出
    SUFFIX ".dylib"
    PREFIX "lib"
    # 允许动态库在 iOS 上使用
    XCODE_ATTRIBUTE_CODE_SIGNING_ALLOWED "YES"
    XCODE_ATTRIBUTE_CODE_SIGN_IDENTITY "-"
    # 安装名
    INSTALL_NAME_DIR "@rpath"
    BUILD_WITH_INSTALL_RPATH TRUE
)

# 导出 gum_trace 符号
target_compile_options(gumTVM PRIVATE -fvisibility=hidden)
