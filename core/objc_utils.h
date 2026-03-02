#ifndef GUMTVM_OBJC_UTILS_H
#define GUMTVM_OBJC_UTILS_H

#include <string>
#include <cstdint>

class ObjCUtils {
public:
    ObjCUtils() = delete;
    ~ObjCUtils() = delete;

    // 尝试通过地址解析 ObjC 方法签名 (例如 "-[NSString length]")
    static std::string resolve_objc_method(uintptr_t address);

    // 获取 ObjC 类名 (如果地址指向一个 ObjC 对象)
    static std::string get_class_name(uintptr_t address);
};

#endif // GUMTVM_OBJC_UTILS_H
