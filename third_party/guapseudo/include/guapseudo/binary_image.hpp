#pragma once

#include "guapseudo/model.hpp"

#include <string>
#include <vector>

namespace guapseudo {

class BinaryImageLoader {
public:
    static BinaryImage load_file(const std::string& path, std::uint64_t raw_base = 0x1000);
    static BinaryImage load_hex(const std::string& text, std::uint64_t base, std::uint64_t entry);

private:
    static BinaryImage load_raw(const std::vector<std::uint8_t>& bytes,
                                const std::string& source_name,
                                std::uint64_t base,
                                std::uint64_t entry);
    static bool try_load_elf64(const std::vector<std::uint8_t>& bytes,
                               const std::string& source_name,
                               BinaryImage& result);
    static bool try_load_pe32_plus(const std::vector<std::uint8_t>& bytes,
                                   const std::string& source_name,
                                   BinaryImage& result);
};

} // namespace guapseudo

