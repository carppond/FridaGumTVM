// ==================== gumTVM iOS Frida 注入脚本 ====================
//
// 使用前:
//   1. SSH 到设备，把 libgumTVM.dylib 复制到 App 沙盒 tmp 目录
//   2. ldid -S 签名
//   3. frida -U <PID> -l gumTrace_ios.js
//
// ================================================================

// ==================== 配置区域 ====================

var trace_mode = "objc";

// --- ObjC 模式 ---
var objc_class = "SGHomeViewController";
var objc_method = "duoduoButtonClicked";
var objc_is_class_method = false;

// --- Offset 模式 ---
var Module_name = "TargetApp";
var target_offset = 0x12345;

// --- 通用 ---
var trace_file_name = "trace.txt";

// ==================== 加载逻辑 ====================

function getAppTmpDir() {
    var fn = new NativeFunction(
        Module.findExportByName("Foundation", "NSTemporaryDirectory"),
        'pointer', []
    );
    return ObjC.Object(fn()).toString();
}

function loadGumTVM() {
    var existing = Module.findBaseAddress("libgumTVM.dylib");
    if (existing) {
        console.log("[*] libgumTVM.dylib already loaded at: " + existing);
        return true;
    }

    // 从 App 沙盒 tmp 目录加载
    var appTmp = getAppTmpDir();
    var dylibPath = appTmp + "libgumTVM.dylib";
    console.log("[*] Loading from: " + dylibPath);

    try {
        var mod = Module.load(dylibPath);
        console.log("[*] Loaded at: " + mod.base);
        return true;
    } catch (e) {
        console.log("[!] Load failed: " + e.message.split('\n')[0]);
        console.log("");
        console.log("[!] Fix: SSH to device and run:");
        console.log("    cp /var/tmp/gumTVM/libgumTVM.dylib " + dylibPath);
        console.log("    ldid -S " + dylibPath);
        return false;
    }
}

// ==================== 追踪逻辑 ====================

function callGumTrace(moduleName, offset, outputFile) {
    var gum_trace_ptr = Module.findExportByName("libgumTVM.dylib", "gum_trace");
    if (!gum_trace_ptr) {
        console.log("[!] gum_trace export not found");
        return false;
    }

    // 使用 App 沙盒 tmp 目录作为输出路径
    var appTmp = getAppTmpDir();
    var fullOutputPath = appTmp + outputFile;

    var gum_trace = new NativeFunction(gum_trace_ptr, 'void', ['pointer', 'uint64', 'pointer']);
    gum_trace(
        Memory.allocUtf8String(moduleName),
        offset,
        Memory.allocUtf8String(fullOutputPath)
    );

    console.log("[*] Tracing active:");
    console.log("[*]   module: " + moduleName);
    console.log("[*]   offset: 0x" + offset.toString(16));
    console.log("[*]   output: " + fullOutputPath);
    return true;
}

function resolveObjcMethod(className, methodName, isClassMethod) {
    var fullName = (isClassMethod ? "+[" : "-[") + className + " " + methodName + "]";

    var cls = ObjC.classes[className];
    if (!cls) {
        console.log("[!] ObjC class not found: " + className);
        return null;
    }

    var method = isClassMethod
        ? cls["+ " + methodName]
        : cls["- " + methodName];

    if (!method) {
        console.log("[!] Method not found: " + fullName);
        var methods = cls.$ownMethods;
        for (var i = 0; i < methods.length; i++) {
            if (methods[i].indexOf(methodName) !== -1) {
                console.log("    " + methods[i]);
            }
        }
        return null;
    }

    var imp = method.implementation;
    var moduleInfo = Process.findModuleByAddress(imp);
    if (!moduleInfo) {
        console.log("[!] Cannot find module for IMP");
        return null;
    }

    var offset = imp.sub(moduleInfo.base).toUInt32();
    console.log("[*] " + fullName);
    console.log("[*]   IMP:    " + imp);
    console.log("[*]   Module: " + moduleInfo.name);
    console.log("[*]   Offset: 0x" + offset.toString(16));

    return { moduleName: moduleInfo.name, offset: offset, fullName: fullName };
}

// ==================== 入口 ====================

function main() {
    console.log("========================================");
    console.log("  gumTVM iOS Tracer");
    console.log("========================================");

    if (!loadGumTVM()) return;

    setTimeout(function() {
        if (trace_mode === "objc") {
            var info = resolveObjcMethod(objc_class, objc_method, objc_is_class_method);
            if (!info) return;
            console.log("[*] Waiting for: " + info.fullName);
            callGumTrace(info.moduleName, info.offset, trace_file_name);
        } else {
            callGumTrace(Module_name, target_offset, trace_file_name);
        }
    }, 200);
}

setImmediate(main);
