#include "hex_dump.h"
#include <iomanip>
#include <cctype>

void HexDump::Dump(std::stringstream& logbuf) const {
    size_t offset = 0;
    while (offset < byte_count_) {
        logbuf << std::hex << std::setw(16) << std::setfill('0') << (address_ + offset) << ": ";

        std::string ascii;
        for (size_t i = 0; i < 16; ++i) {
            if (offset + i < byte_count_) {
                uint8_t byte = buffer_[offset + i];
                logbuf << std::setw(2) << std::setfill('0') << std::hex << static_cast<int>(byte) << " ";
                ascii += (std::isprint(byte) ? static_cast<char>(byte) : '.');
            } else {
                logbuf << "   ";
                ascii += " ";
            }
            if (i == 7) logbuf << " ";
        }

        logbuf << " |" << ascii << "|" << std::endl;
        offset += 16;
    }
}
