#!/bin/bash
set -e

# ==================== 非越狱 IPA 注入脚本 ====================
#
# 使用方法:
#   ./scripts/inject_ipa.sh <input.ipa> <signing_identity> [output.ipa]
#
# 参数:
#   input.ipa          - 目标 IPA 文件
#   signing_identity   - 代码签名标识 (如 "Apple Development: xxx@xxx.com (XXXXXXXXXX)")
#                        使用 `security find-identity -v -p codesigning` 查看可用标识
#   output.ipa         - 输出 IPA 文件 (默认: <input>_injected.ipa)
#
# 前置条件:
#   1. 已构建 libgumTVM.dylib (运行 build_ios.sh)
#   2. 安装 insert_dylib: brew install insert-dylib 或从源码编译
#      https://github.com/tyilo/insert_dylib
#   3. 有效的 iOS 开发者签名证书
#   4. 对应的 mobileprovision 文件 (放到与脚本同目录或指定路径)
#
# ================================================================

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

INPUT_IPA="$1"
SIGNING_ID="$2"
OUTPUT_IPA="${3:-}"

if [ -z "$INPUT_IPA" ] || [ -z "$SIGNING_ID" ]; then
    echo "Usage: $0 <input.ipa> <signing_identity> [output.ipa]"
    echo ""
    echo "Example:"
    echo "  $0 Target.ipa \"Apple Development: dev@example.com (XXXXXXXXXX)\""
    echo ""
    echo "Available signing identities:"
    security find-identity -v -p codesigning | head -10
    exit 1
fi

if [ ! -f "$INPUT_IPA" ]; then
    echo "❌ Error: IPA file not found: $INPUT_IPA"
    exit 1
fi

DYLIB_PATH="$PROJECT_DIR/build/ios-arm64/libgumTVM.dylib"
if [ ! -f "$DYLIB_PATH" ]; then
    echo "❌ Error: libgumTVM.dylib not found. Run build_ios.sh first."
    exit 1
fi

# 设置输出文件名
if [ -z "$OUTPUT_IPA" ]; then
    BASENAME=$(basename "$INPUT_IPA" .ipa)
    OUTPUT_IPA="$(dirname "$INPUT_IPA")/${BASENAME}_injected.ipa"
fi

# 检查 insert_dylib
if ! command -v insert_dylib &>/dev/null; then
    echo "❌ Error: insert_dylib not found."
    echo "Install: brew install insert-dylib"
    echo "Or build from: https://github.com/tyilo/insert_dylib"
    exit 1
fi

echo "=== gumTVM IPA Injection ==="
echo "Input:  $INPUT_IPA"
echo "Output: $OUTPUT_IPA"
echo ""

# 创建临时工作目录
WORK_DIR=$(mktemp -d)
trap "rm -rf $WORK_DIR" EXIT

# 解压 IPA
echo "[1/6] Extracting IPA..."
unzip -q "$INPUT_IPA" -d "$WORK_DIR"

# 找到 .app 目录
APP_DIR=$(find "$WORK_DIR/Payload" -name "*.app" -type d | head -1)
if [ -z "$APP_DIR" ]; then
    echo "❌ Error: No .app found in IPA"
    exit 1
fi

APP_NAME=$(basename "$APP_DIR" .app)
echo "  App: $APP_NAME"

# 找到主二进制
MAIN_BINARY="$APP_DIR/$APP_NAME"
if [ ! -f "$MAIN_BINARY" ]; then
    # 尝试从 Info.plist 获取
    EXEC_NAME=$(/usr/libexec/PlistBuddy -c "Print :CFBundleExecutable" "$APP_DIR/Info.plist" 2>/dev/null || echo "")
    if [ -n "$EXEC_NAME" ]; then
        MAIN_BINARY="$APP_DIR/$EXEC_NAME"
    fi
fi

if [ ! -f "$MAIN_BINARY" ]; then
    echo "❌ Error: Main binary not found"
    exit 1
fi
echo "  Binary: $(basename "$MAIN_BINARY")"

# 复制 dylib 和配置文件
echo "[2/6] Injecting dylib..."
mkdir -p "$APP_DIR/Frameworks"
cp "$DYLIB_PATH" "$APP_DIR/Frameworks/"

# 复制配置文件（如果存在）
CONFIG_FILE="$PROJECT_DIR/config/trace_config.json"
if [ -f "$CONFIG_FILE" ]; then
    cp "$CONFIG_FILE" "$APP_DIR/"
    echo "  Config file copied"
fi

# 使用 insert_dylib 添加 LC_LOAD_DYLIB
echo "[3/6] Patching Mach-O binary..."
insert_dylib --strip-codesig --inplace "@rpath/libgumTVM.dylib" "$MAIN_BINARY"

# 移除旧签名和 _CodeSignature
echo "[4/6] Removing old signatures..."
rm -rf "$APP_DIR/_CodeSignature"
find "$APP_DIR" -name "*.mobileprovision" -delete

# 复制 mobileprovision (如果提供)
PROVISION_FILE=$(find "$SCRIPT_DIR" -name "*.mobileprovision" | head -1)
if [ -n "$PROVISION_FILE" ]; then
    cp "$PROVISION_FILE" "$APP_DIR/embedded.mobileprovision"
    echo "  Provisioning profile: $(basename "$PROVISION_FILE")"
fi

# 签名所有 Frameworks
echo "[5/6] Code signing..."
find "$APP_DIR/Frameworks" -name "*.dylib" -o -name "*.framework" | while read -r item; do
    codesign -fs "$SIGNING_ID" "$item" 2>/dev/null || true
done

# 签名主 App
codesign -fs "$SIGNING_ID" "$APP_DIR"

# 重新打包
echo "[6/6] Repacking IPA..."
cd "$WORK_DIR"
zip -qr "$OUTPUT_IPA" Payload/

echo ""
echo "=== Injection Complete ==="
echo "Output: $OUTPUT_IPA"
echo ""
echo "Install with:"
echo "  ideviceinstaller -i \"$OUTPUT_IPA\""
echo "  # or use Xcode Devices / Apple Configurator"
