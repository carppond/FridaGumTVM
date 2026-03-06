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

    // 从 objc_msgSend 的 x0(self) 和 x1(SEL) 解析出方法签名
    // 返回 "-[ClassName selector]" 或 "+[ClassName selector]"
    static std::string resolve_msg_send(uintptr_t self_ptr, uintptr_t sel_ptr);
};

#endif // GUMTVM_OBJC_UTILS_H
