#include "guapseudo/binary_image.hpp"

#include <algorithm>
#include <cctype>
#include <fstream>
#include <limits>
#include <sstream>
#include <stdexcept>

namespace guapseudo {
namespace {

std::uint16_t read_u16(const std::vector<std::uint8_t>& bytes, std::size_t offset) {
    if (offset + 2 > bytes.size()) return 0;
    return static_cast<std::uint16_t>(bytes[offset]) |
           (static_cast<std::uint16_t>(bytes[offset + 1]) << 8U);
}

std::uint32_t read_u32(const std::vector<std::uint8_t>& bytes, std::size_t offset) {
    if (offset + 4 > bytes.size()) return 0;
    return static_cast<std::uint32_t>(bytes[offset]) |
           (static_cast<std::uint32_t>(bytes[offset + 1]) << 8U) |
           (static_cast<std::uint32_t>(bytes[offset + 2]) << 16U) |
           (static_cast<std::uint32_t>(bytes[offset + 3]) << 24U);
}

std::uint64_t read_u64(const std::vector<std::uint8_t>& bytes, std::size_t offset) {
    if (offset + 8 > bytes.size()) return 0;
    std::uint64_t value = 0;
    for (unsigned i = 0; i < 8; ++i) {
        value |= static_cast<std::uint64_t>(bytes[offset + i]) << (i * 8U);
    }
    return value;
}

} // namespace

BinaryImage BinaryImageLoader::load_file(const std::string& path, std::uint64_t raw_base) {
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        throw std::runtime_error("cannot open input: " + path);
    }

    std::vector<std::uint8_t> bytes((std::istreambuf_iterator<char>(file)),
                                    std::istreambuf_iterator<char>());
    if (bytes.empty()) {
        throw std::runtime_error("input is empty: " + path);
    }

    BinaryImage result;
    if (try_load_elf64(bytes, path, result) || try_load_pe32_plus(bytes, path, result)) {
        return result;
    }
    return load_raw(bytes, path, raw_base, raw_base);
}

BinaryImage BinaryImageLoader::load_hex(const std::string& text,
                                        std::uint64_t base,
                                        std::uint64_t entry) {
    std::vector<std::uint8_t> bytes;
    std::string normalized = text;
    std::replace(normalized.begin(), normalized.end(), ',', ' ');
    std::stringstream stream(normalized);
    std::string part;
    while (stream >> part) {
        if (part.size() >= 2 && part[0] == '0' && (part[1] == 'x' || part[1] == 'X')) {
            part.erase(0, 2);
        }
        if (part.size() > 2 || part.empty()) {
            throw std::runtime_error("invalid hex byte: " + part);
        }
        unsigned value = 0;
        for (char c : part) {
            if (!std::isxdigit(static_cast<unsigned char>(c))) {
                throw std::runtime_error("invalid hex byte: " + part);
            }
            const auto digit = std::isdigit(static_cast<unsigned char>(c))
                                   ? static_cast<unsigned>(c - '0')
                                   : static_cast<unsigned>(std::tolower(static_cast<unsigned char>(c)) - 'a' + 10);
            value = value * 16U + digit;
        }
        bytes.push_back(static_cast<std::uint8_t>(value));
    }
    if (bytes.empty()) {
        throw std::runtime_error("hex input contains no bytes");
    }
    return load_raw(bytes, "<hex>", base, entry);
}

BinaryImage BinaryImageLoader::load_raw(const std::vector<std::uint8_t>& bytes,
                                        const std::string& source_name,
                                        std::uint64_t base,
                                        std::uint64_t entry) {
    BinaryImage result;
    result.format = ImageFormat::Raw;
    result.source_name = source_name;
    result.code_base = base;
    result.entry = entry;
    result.code = bytes;
    return result;
}

bool BinaryImageLoader::try_load_elf64(const std::vector<std::uint8_t>& bytes,
                                       const std::string& source_name,
                                       BinaryImage& result) {
    if (bytes.size() < 64 || bytes[0] != 0x7f || bytes[1] != 'E' || bytes[2] != 'L' ||
        bytes[3] != 'F' || bytes[4] != 2 || bytes[5] != 1) {
        return false;
    }

    const std::uint64_t entry = read_u64(bytes, 0x18);
    const std::uint64_t program_header_offset = read_u64(bytes, 0x20);
    const std::uint16_t program_header_size = read_u16(bytes, 0x36);
    const std::uint16_t program_header_count = read_u16(bytes, 0x38);
    if (program_header_size < 56 || program_header_count == 0) return false;

    std::size_t selected = std::numeric_limits<std::size_t>::max();
    for (std::uint16_t i = 0; i < program_header_count; ++i) {
        const std::size_t offset = static_cast<std::size_t>(program_header_offset) +
                                   static_cast<std::size_t>(i) * program_header_size;
        if (offset + 56 > bytes.size()) break;
        const auto type = read_u32(bytes, offset);
        const auto flags = read_u32(bytes, offset + 4);
        const auto virtual_address = read_u64(bytes, offset + 16);
        const auto file_offset = read_u64(bytes, offset + 8);
        const auto file_size = read_u64(bytes, offset + 32);
        if (type == 1 && (flags & 1U) != 0 && file_size != 0 &&
            file_offset < bytes.size() && entry >= virtual_address &&
            entry < virtual_address + file_size) {
            selected = offset;
            break;
        }
        if (selected == std::numeric_limits<std::size_t>::max() &&
            type == 1 && (flags & 1U) != 0 && file_size != 0) {
            selected = offset;
        }
    }
    if (selected == std::numeric_limits<std::size_t>::max()) return false;

    const auto code_base = read_u64(bytes, selected + 16);
    const auto file_offset = read_u64(bytes, selected + 8);
    const auto file_size = read_u64(bytes, selected + 32);
    const auto available = static_cast<std::uint64_t>(bytes.size()) -
                           std::min<std::uint64_t>(file_offset, bytes.size());
    const auto copy_size = std::min(file_size, available);
    if (copy_size == 0) return false;

    result.format = ImageFormat::Elf64;
    result.source_name = source_name;
    result.code_base = code_base;
    result.entry = (entry >= code_base && entry < code_base + copy_size) ? entry : code_base;
    result.code.assign(bytes.begin() + static_cast<std::ptrdiff_t>(file_offset),
                       bytes.begin() + static_cast<std::ptrdiff_t>(file_offset + copy_size));
    return true;
}

bool BinaryImageLoader::try_load_pe32_plus(const std::vector<std::uint8_t>& bytes,
                                           const std::string& source_name,
                                           BinaryImage& result) {
    if (bytes.size() < 0x40 || bytes[0] != 'M' || bytes[1] != 'Z') return false;
    const auto pe_offset = read_u32(bytes, 0x3c);
    if (pe_offset + 24 > bytes.size() || bytes[pe_offset] != 'P' || bytes[pe_offset + 1] != 'E' ||
        bytes[pe_offset + 2] != 0 || bytes[pe_offset + 3] != 0) {
        return false;
    }

    const auto section_count = read_u16(bytes, pe_offset + 6);
    const auto optional_size = read_u16(bytes, pe_offset + 20);
    const auto optional_offset = static_cast<std::size_t>(pe_offset) + 24;
    if (optional_offset + optional_size > bytes.size() || read_u16(bytes, optional_offset) != 0x20b) {
        return false;
    }

    const auto entry_rva = read_u32(bytes, optional_offset + 16);
    const auto image_base = read_u64(bytes, optional_offset + 24);
    const auto sections_offset = optional_offset + optional_size;
    std::size_t selected = std::numeric_limits<std::size_t>::max();
    for (std::uint16_t i = 0; i < section_count; ++i) {
        const auto offset = sections_offset + static_cast<std::size_t>(i) * 40;
        if (offset + 40 > bytes.size()) break;
        const auto virtual_address = read_u32(bytes, offset + 12);
        const auto raw_size = read_u32(bytes, offset + 16);
        const auto raw_offset = read_u32(bytes, offset + 20);
        const auto characteristics = read_u32(bytes, offset + 36);
        if ((characteristics & 0x20000000U) == 0 || raw_size == 0 || raw_offset >= bytes.size()) continue;
        if (entry_rva >= virtual_address && entry_rva < virtual_address + raw_size) {
            selected = offset;
            break;
        }
        if (selected == std::numeric_limits<std::size_t>::max()) selected = offset;
    }
    if (selected == std::numeric_limits<std::size_t>::max()) return false;

    const auto virtual_address = read_u32(bytes, selected + 12);
    const auto raw_size = read_u32(bytes, selected + 16);
    const auto raw_offset = read_u32(bytes, selected + 20);
    const auto copy_size = std::min<std::uint64_t>(raw_size, bytes.size() - raw_offset);
    if (copy_size == 0) return false;

    result.format = ImageFormat::Pe32Plus;
    result.source_name = source_name;
    result.code_base = image_base + virtual_address;
    result.entry = (entry_rva >= virtual_address && entry_rva < virtual_address + copy_size)
                       ? image_base + entry_rva
                       : result.code_base;
    result.code.assign(bytes.begin() + static_cast<std::ptrdiff_t>(raw_offset),
                       bytes.begin() + static_cast<std::ptrdiff_t>(raw_offset + copy_size));
    return true;
}

} // namespace guapseudo

