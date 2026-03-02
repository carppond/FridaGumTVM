#!/bin/bash
set -e

# ==================== 越狱设备注入脚本 ====================
#
# 使用方法:
#   方式1 - DYLD_INSERT_LIBRARIES 注入:
#     ./scripts/inject_jailbreak.sh dyld <bundle_id>
#
#   方式2 - Frida 注入:
#     ./scripts/inject_jailbreak.sh frida <bundle_id_or_pid>
#
#   方式3 - 仅推送文件到设备:
#     ./scripts/inject_jailbreak.sh push
#
# 前置条件:
#   1. 已构建 libgumTVM.dylib (运行 build_ios.sh)
#   2. 越狱设备通过 USB 连接
#   3. 安装了 iproxy / ssh (apt install usbmuxd / openssh)
#   4. Frida 方式需要 frida-server 在设备上运行
#
# ================================================================

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

MODE="${1:-push}"
TARGET="${2:-}"
DEVICE_PORT="${SSH_PORT:-2222}"  # iproxy 端口
DEVICE_USER="${SSH_USER:-root}"
DEVICE_PASS="${SSH_PASS:-alpine}"
REMOTE_DIR="/var/mobile/gumTVM"

DYLIB_PATH="$PROJECT_DIR/build/ios-arm64/libgumTVM.dylib"
CONFIG_PATH="$PROJECT_DIR/config/trace_config.json"

if [ ! -f "$DYLIB_PATH" ]; then
    echo "❌ Error: libgumTVM.dylib not found. Run build_ios.sh first."
    exit 1
fi

# SSH 执行命令
ssh_exec() {
    sshpass -p "$DEVICE_PASS" ssh -o StrictHostKeyChecking=no -p "$DEVICE_PORT" "$DEVICE_USER@localhost" "$@"
}

# SCP 推送文件
scp_push() {
    sshpass -p "$DEVICE_PASS" scp -o StrictHostKeyChecking=no -P "$DEVICE_PORT" "$1" "$DEVICE_USER@localhost:$2"
}

push_files() {
    echo "=== Pushing files to device ==="

    # 启动 iproxy (如果没有运行)
    if ! pgrep -x iproxy >/dev/null 2>&1; then
        echo "Starting iproxy..."
        iproxy "$DEVICE_PORT" 22 &
        sleep 1
    fi

    # 创建远程目录
    ssh_exec "mkdir -p $REMOTE_DIR"

    # 推送文件
    echo "Pushing libgumTVM.dylib..."
    scp_push "$DYLIB_PATH" "$REMOTE_DIR/libgumTVM.dylib"

    if [ -f "$CONFIG_PATH" ]; then
        echo "Pushing trace_config.json..."
        scp_push "$CONFIG_PATH" "$REMOTE_DIR/trace_config.json"
    fi

    # 签名 dylib (在设备上)
    ssh_exec "ldid -S $REMOTE_DIR/libgumTVM.dylib" 2>/dev/null || true

    echo ""
    echo "Files pushed to: $REMOTE_DIR"
    echo "  - libgumTVM.dylib"
    [ -f "$CONFIG_PATH" ] && echo "  - trace_config.json"
}

case "$MODE" in
    push)
        push_files
        ;;

    dyld)
        if [ -z "$TARGET" ]; then
            echo "Usage: $0 dyld <bundle_id>"
            echo "Example: $0 dyld com.example.app"
            exit 1
        fi

        push_files
        echo ""
        echo "=== DYLD_INSERT_LIBRARIES Injection ==="
        echo "Target: $TARGET"
        echo ""
        echo "Run on device (via SSH):"
        echo "  DYLD_INSERT_LIBRARIES=$REMOTE_DIR/libgumTVM.dylib open $TARGET"
        echo ""
        echo "Or kill and relaunch:"
        echo "  killall \"$TARGET\" 2>/dev/null; DYLD_INSERT_LIBRARIES=$REMOTE_DIR/libgumTVM.dylib open $TARGET"
        echo ""
        echo "Trace output will be in: /tmp/gumTVM/"
        ;;

    frida)
        if [ -z "$TARGET" ]; then
            echo "Usage: $0 frida <bundle_id_or_pid>"
            echo "Example: $0 frida com.example.app"
            exit 1
        fi

        push_files
        echo ""
        echo "=== Frida Injection ==="

        # 生成 Frida JS 脚本
        FRIDA_SCRIPT="$PROJECT_DIR/build/gumTrace_ios.js"
        cat > "$FRIDA_SCRIPT" << 'FRIDA_EOF'
// gumTVM iOS Frida 注入脚本
// 修改以下配置后使用

var remote_dylib_path = "/var/mobile/gumTVM/libgumTVM.dylib";

function inject() {
    try {
        var module = Module.load(remote_dylib_path);
        console.log("[*] libgumTVM.dylib loaded at: " + module.base);

        // 如果需要手动调用 gum_trace (不使用自动配置)
        // var gum_trace = new NativeFunction(
        //     Module.findExportByName("libgumTVM.dylib", "gum_trace"),
        //     'void', ['pointer', 'uint64', 'pointer']
        // );
        // gum_trace(
        //     Memory.allocUtf8String("TargetModule"),
        //     0x12345,
        //     Memory.allocUtf8String("trace.txt")
        // );

        console.log("[*] gumTVM tracer active (using auto-config from trace_config.json)");
    } catch(e) {
        console.log("[!] Error: " + e.message);
    }
}

// 立即注入 或 等待特定模块加载后注入
inject();
FRIDA_EOF

        echo "Frida script generated: $FRIDA_SCRIPT"
        echo ""
        echo "Run:"
        echo "  frida -U -f $TARGET -l $FRIDA_SCRIPT --no-pause"
        echo "  # or for running process:"
        echo "  frida -U $TARGET -l $FRIDA_SCRIPT"
        ;;

    *)
        echo "Usage: $0 <push|dyld|frida> [target]"
        exit 1
        ;;
esac
