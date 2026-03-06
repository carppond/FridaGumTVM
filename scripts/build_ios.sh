#!/bin/bash
set -e

# ==================== gumTVM iOS 构建脚本 ====================
#
# 使用方法:
#   ./scripts/build_ios.sh [debug|release]
#
# 前置条件:
#   1. 安装 Xcode 和 Command Line Tools
#   2. 下载 frida-gum-devkit-*-ios-arm64.tar.xz 并解压到 prebuild/ios-arm64/
#      下载地址: https://github.com/frida/frida/releases
#
# ================================================================

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BUILD_TYPE="${1:-Release}"

# 验证 devkit
DEVKIT_DIR="$PROJECT_DIR/prebuild/ios-arm64"
if [ ! -f "$DEVKIT_DIR/libfrida-gum.a" ]; then
    echo "❌ Error: frida-gum devkit not found!"
    echo ""
    echo "Please download the iOS arm64 devkit from:"
    echo "  https://github.com/frida/frida/releases"
    echo ""
    echo "Look for: frida-gum-devkit-<VERSION>-ios-arm64.tar.xz"
    echo ""
    echo "Then extract it:"
    echo "  mkdir -p $DEVKIT_DIR"
    echo "  tar -xJf frida-gum-devkit-*-ios-arm64.tar.xz -C $DEVKIT_DIR"
    echo ""
    exit 1
fi

echo "=== gumTVM iOS Build ==="
echo "Build type: $BUILD_TYPE"
echo "Devkit: $DEVKIT_DIR"
echo ""

# 构建
BUILD_DIR="$PROJECT_DIR/build/ios-arm64"
mkdir -p "$BUILD_DIR"

cmake -B "$BUILD_DIR" -S "$PROJECT_DIR" \
    -DCMAKE_SYSTEM_NAME=iOS \
    -DCMAKE_OSX_ARCHITECTURES=arm64 \
    -DCMAKE_OSX_DEPLOYMENT_TARGET=14.0 \
    -DCMAKE_BUILD_TYPE="$BUILD_TYPE" \
    -G "Unix Makefiles"

cmake --build "$BUILD_DIR" -j$(sysctl -n hw.ncpu)

# 输出结果
DYLIB_PATH="$BUILD_DIR/libgumTVM.dylib"
if [ -f "$DYLIB_PATH" ]; then
    echo ""
    echo "=== Build Successful ==="
    echo "Output: $DYLIB_PATH"
    echo "Size: $(ls -lh "$DYLIB_PATH" | awk '{print $5}')"
    echo ""

    # ldid 签名（RootHide 越狱需要）
    if command -v ldid &>/dev/null; then
        ldid -S "$DYLIB_PATH"
        echo "ldid signed: $DYLIB_PATH"
    else
        echo "⚠️  ldid not found, please run: ldid -S $DYLIB_PATH"
    fi
else
    echo "❌ Build failed: dylib not found"
    exit 1
fi
