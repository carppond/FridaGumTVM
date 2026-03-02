// ==================== gumTVM iOS Frida 注入脚本 ====================
//
// 使用方法:
//   越狱设备:
//     frida -U -f <bundle_id> -l gumTrace_ios.js --no-pause
//     frida -U <app_name_or_pid> -l gumTrace_ios.js
//
//   非越狱 (需要 gadget 模式):
//     frida -U -f <bundle_id> -l gumTrace_ios.js --no-pause
//
// ================================================================

// ==================== 配置区域 ====================

// 目标模块名 (dylib 或主二进制)
var Module_name = "TargetApp";

// 目标函数偏移
var target_offset = 0x12345;

// 追踪输出文件名
var trace_file_name = "trace.txt";

// libgumTVM.dylib 在设备上的路径
var dylib_remote_path = "/var/mobile/gumTVM/libgumTVM.dylib";

// 配置文件路径 (如果使用自动配置模式，确保此文件存在)
var config_remote_path = "/tmp/gumTVM/trace_config.json";

// 是否使用自动配置 (true = 从 config 文件读取, false = 使用上面的手动配置)
var use_auto_config = false;

// ==================== 注入逻辑 ====================

function writeConfig(moduleName, offset, outputFile) {
    // 写入配置文件到 /tmp/gumTVM/
    var mkdir_ptr = Module.findExportByName("libSystem.B.dylib", "mkdir");
    var mkdir_fn = new NativeFunction(mkdir_ptr, 'int', ['pointer', 'int']);
    mkdir_fn(Memory.allocUtf8String("/tmp/gumTVM"), 0x1FF); // 0777

    var config = JSON.stringify({
        target_module: moduleName,
        trace_offset: "0x" + offset.toString(16),
        output_file: outputFile
    }, null, 4);

    var fopen = new NativeFunction(
        Module.findExportByName("libSystem.B.dylib", "fopen"),
        'pointer', ['pointer', 'pointer']
    );
    var fwrite = new NativeFunction(
        Module.findExportByName("libSystem.B.dylib", "fwrite"),
        'uint64', ['pointer', 'uint64', 'uint64', 'pointer']
    );
    var fclose = new NativeFunction(
        Module.findExportByName("libSystem.B.dylib", "fclose"),
        'int', ['pointer']
    );

    var configStr = Memory.allocUtf8String(config);
    var fp = fopen(Memory.allocUtf8String(config_remote_path), Memory.allocUtf8String("w"));
    if (!fp.isNull()) {
        fwrite(configStr, 1, config.length, fp);
        fclose(fp);
        console.log("[*] Config written to: " + config_remote_path);
    } else {
        console.log("[!] Failed to write config file");
    }
}

function loadGumTVM() {
    try {
        // 检查是否已经加载
        var existing = Module.findBaseAddress("libgumTVM.dylib");
        if (existing) {
            console.log("[*] libgumTVM.dylib already loaded at: " + existing);
            return true;
        }

        // 加载 dylib
        var module = Module.load(dylib_remote_path);
        console.log("[*] libgumTVM.dylib loaded at: " + module.base);
        return true;
    } catch (e) {
        console.log("[!] Failed to load libgumTVM.dylib: " + e.message);
        console.log("[!] Make sure the file exists at: " + dylib_remote_path);
        return false;
    }
}

function callGumTrace(moduleName, offset, outputFile) {
    var gum_trace_ptr = Module.findExportByName("libgumTVM.dylib", "gum_trace");
    if (!gum_trace_ptr) {
        console.log("[!] gum_trace export not found in libgumTVM.dylib");
        return false;
    }

    console.log("[*] gum_trace found at: " + gum_trace_ptr);
    var gum_trace = new NativeFunction(gum_trace_ptr, 'void', ['pointer', 'uint64', 'pointer']);
    gum_trace(
        Memory.allocUtf8String(moduleName),
        offset,
        Memory.allocUtf8String(outputFile)
    );

    console.log("[*] gum_trace() called successfully");
    console.log("[*]   module: " + moduleName);
    console.log("[*]   offset: 0x" + offset.toString(16));
    console.log("[*]   output: " + outputFile);
    return true;
}

function hookAndTrace(moduleName, offset, outputFile) {
    if (use_auto_config) {
        // 自动配置模式: 先写配置文件，加载 dylib 时 constructor 会自动读取
        writeConfig(moduleName, offset, outputFile);
        if (loadGumTVM()) {
            console.log("[*] Auto-config mode: tracer should start automatically");
        }
    } else {
        // 手动模式: 加载 dylib 后手动调用 gum_trace
        if (loadGumTVM()) {
            // 等待 constructor 执行完成
            setTimeout(function() {
                callGumTrace(moduleName, offset, outputFile);
            }, 100);
        }
    }
}

// ==================== 入口 ====================

function main() {
    console.log("========================================");
    console.log("  gumTVM iOS Tracer - Frida Injection");
    console.log("========================================");
    console.log("[*] Target module: " + Module_name);
    console.log("[*] Target offset: 0x" + target_offset.toString(16));
    console.log("");

    // 检查目标模块是否已加载
    var targetBase = Module.findBaseAddress(Module_name);
    if (targetBase) {
        console.log("[*] Target module already loaded at: " + targetBase);
        hookAndTrace(Module_name, target_offset, trace_file_name);
        return;
    }

    // 模块未加载，Hook dlopen 等待加载
    console.log("[*] Target module not yet loaded, hooking dlopen...");

    // iOS 上 hook dlopen
    var dlopen_ptr = Module.findExportByName("libdyld.dylib", "dlopen");
    if (!dlopen_ptr) {
        dlopen_ptr = Module.findExportByName(null, "dlopen");
    }

    if (dlopen_ptr) {
        Interceptor.attach(dlopen_ptr, {
            onEnter: function(args) {
                if (args[0] && !args[0].isNull()) {
                    this.path = args[0].readUtf8String();
                }
            },
            onLeave: function(retval) {
                if (this.path && this.path.indexOf(Module_name) !== -1) {
                    console.log("[*] dlopen detected: " + this.path);
                    var base = Module.findBaseAddress(Module_name);
                    if (base) {
                        console.log("[*] Module loaded at: " + base);
                        hookAndTrace(Module_name, target_offset, trace_file_name);
                    }
                }
            }
        });
        console.log("[*] dlopen hooked, waiting for module load...");
    }

    // 同时 hook NSBundle 加载 (用于 framework 加载)
    try {
        var NSBundle = ObjC.classes.NSBundle;
        if (NSBundle && NSBundle["- load"]) {
            Interceptor.attach(NSBundle["- load"].implementation, {
                onLeave: function(retval) {
                    var base = Module.findBaseAddress(Module_name);
                    if (base) {
                        console.log("[*] NSBundle load detected target module at: " + base);
                        hookAndTrace(Module_name, target_offset, trace_file_name);
                    }
                }
            });
            console.log("[*] NSBundle load hooked");
        }
    } catch(e) {
        // ObjC runtime not available
    }
}

setImmediate(main);
