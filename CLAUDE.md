# FridaGumTVM - iOS 指令级追踪器

基于 Frida-GUM 的 iOS ARM64 指令级追踪框架，用于安全研究和逆向分析。

## 项目结构

```
core/                           # 核心 C++/ObjC 实现
├── common.h                    # 日志宏(LOGI/LOGE)、类型定义、PAC strip、线程 ID
├── gum_init.cpp                # constructor(101) 初始化 frida-gum
├── entry.h/cpp                 # 导出 C API: gum_trace, gum_trace_exclude/include_module
├── instruction_tracer_manager.h/cpp  # 核心单例管理器: Stalker、模块缓存、智能过滤
├── instruction_callback.h/cpp  # transform_callback + instruction_callback（最大文件 ~800行）
├── custom_hook.h/cpp           # Interceptor enter/leave 钩子，控制 follow/unfollow
├── logger_manager.h/cpp        # 文件 I/O (256KB缓冲)、vm_read_overwrite 安全读、hexdump
├── macho_utils.h/cpp           # Mach-O 解析 __stubs/__stub_helper 段
├── objc_utils.h/mm             # ObjC 运行时方法解析（.mm 因 ObjC 语法）
└── hex_dump.h/cpp              # 十六进制 dump 格式化
scripts/
├── build_ios.sh                # 构建脚本（cmake + ldid 签名）
├── gumTrace_ios.js             # Frida 注入脚本（ObjC/offset 模式 + exclude/include 配置）
├── inject_jailbreak.sh         # 越狱设备部署
└── inject_ipa.sh               # 非越狱 IPA 注入
config/trace_config.json        # 自动加载配置模板
prebuild/ios-arm64/             # frida-gum-devkit（手动下载放置）
```

## 构建

```bash
# 前置: prebuild/ios-arm64/ 下需要 frida-gum devkit
# 下载: https://github.com/frida/frida/releases → frida-gum-devkit-*-ios-arm64.tar.xz
bash scripts/build_ios.sh        # 输出: build/ios-arm64/libgumTVM.dylib (ldid 签名)
```

- CMake 交叉编译 iOS arm64，C++17，`-O3 -flto`
- 依赖: frida-gum (static), Foundation, CoreFoundation, libdl, libpthread
- 签名使用 `ldid -S`（RootHide 越狱需要，不用 codesign）

## 部署（RootHide 越狱）

```bash
# 1. scp 到 App 沙盒 tmp 目录（App 沙盒外无法加载）
scp build/ios-arm64/libgumTVM.dylib root@<IP>:<App沙盒>/tmp/

# 2. Frida attach 模式（RootHide 不支持 spawn -f）
frida -U <进程名> -l scripts/gumTrace_ios.js
```

## 关键架构

### 初始化顺序
1. `constructor(101)`: `gum_init_embedded()` 初始化 GUM
2. `constructor(102)`: 搜索 trace_config.json 自动配置
3. 手动调用: `gum_trace()` 或 Frida JS `callGumTrace()`

### 追踪流程
- `gum_trace()` → `init()` + `run_attach()` → Interceptor hook 目标函数
- `hook_common_enter` → `gum_stalker_follow_me()` 开始逐指令追踪
- `transform_callback` 每基本块调用，`should_trace_address()` 过滤
- `instruction_callback` 每条指令调用，记录寄存器/内存/调用信息
- `hook_common_leave` → `unfollow()` + 关闭日志

### 智能跨模块追踪
`should_trace_address()` 判断链:
1. 主模块 → 追踪（快速路径）
2. 范围缓存 O(log n) 查找 → 命中返回
3. 缓存未命中 → `dladdr()` 获取模块信息（仅首次）
4. 自身 libgumTVM.dylib → 跳过（按基址比较）
5. exclude 列表 → 不追踪（子串匹配）
6. include 列表 → 强制追踪
7. 系统库 `/usr/lib/`, `/System/Library/` → 不追踪
8. 其余 → App 代码，自动追踪
9. 缓存模块范围（`gum_process_find_module_by_name` 获取）

### 性能要点
- `module_trace_cache`: `std::map<base, CachedModuleInfo>` + `upper_bound` 做范围查找
- `instruction_callback` 内零 `dladdr` 调用，全部从缓存读取
- 文件 I/O: ofstream 256KB 写缓冲
- LSE 原子指令（LDXR/STXR）跳过，避免破坏排他性

## 代码约定

- **命名**: 类 PascalCase，方法/变量 snake_case，宏 UPPER_SNAKE
- **日志**: `LOGI()`/`LOGE()` 到 stderr，trace 数据到文件
- **iOS 适配**:
  - `vm_read_overwrite()` 替代 Android `process_vm_readv`
  - `vm_region_64()` 替代 `mincore` 做地址验证
  - `dladdr()` 替代 Android xDL
  - `__stubs/__stub_helper` 替代 ELF PLT
  - `ptrauth_strip` 仅 `__arm64e__` 条件编译
- **类型注意**: iOS arm64 `uintptr_t` = `unsigned long`，`uint64_t` = `unsigned long long`，跨类型赋值需显式转换

## Trace 输出格式

```
==================== TRACE START ====================
  module: TargetApp
  thread: 12345
=====================================================
0x1234      mov    x0, x1   ;r[x1_1=0x400000]
   w[x0_1=0x400000]
0x1238      bl     #0x2000  (0x2000)
call addr: 0x2000 [SomeLib!some_function]
---------- >> SomeSDK (0x102a00000) ----------
[SomeSDK] 0x1234   ldr    x2, [x3, #8]   ;r[x3_1=0x400100]
   mem[r]_1 addr[ 0x400108 ] size:8 value:0x123456789abcdef
---------- >> TargetApp (0x100abc000) ----------
0x123c      ret
==================== TRACE END ======================
```

## 待实现功能

- 追踪所有线程（当前仅触发线程）
- 持续追踪模式（不因函数 return 停止）
- 同时 hook 多个方法
