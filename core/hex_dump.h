#ifndef GUMTVM_HEX_DUMP_H
#define GUMTVM_HEX_DUMP_H

#include "common.h"
#include <sstream>

class HexDump {
public:
    HexDump(const uint8_t* buffer, size_t byte_count, uint64_t address)
        : buffer_(buffer), byte_count_(byte_count), address_(address) {}

    void Dump(std::stringstream& logbuf) const;

private:
    const uint8_t* buffer_;
    uint64_t address_;
    const size_t byte_count_;
    DISALLOW_COPY_AND_ASSIGN(HexDump);
};

inline std::stringstream& operator<<(std::stringstream& logbuf, const HexDump& rhs) {
    rhs.Dump(logbuf);
    return logbuf;
}

#endif // GUMTVM_HEX_DUMP_H
