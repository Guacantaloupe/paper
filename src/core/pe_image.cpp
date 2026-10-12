#include "paper/core/pe_image.hpp"

#include <algorithm>
#include <cstring>
#include <fstream>
#include <limits>

namespace paper {
namespace {

std::uint16_t u16(const std::vector<std::uint8_t>& bytes, std::size_t offset) {
    if (offset + 2 > bytes.size()) return 0;
    return static_cast<std::uint16_t>(bytes[offset] | (static_cast<std::uint16_t>(bytes[offset + 1]) << 8));
}

std::uint32_t u32(const std::vector<std::uint8_t>& bytes, std::size_t offset) {
    if (offset + 4 > bytes.size()) return 0;
    return static_cast<std::uint32_t>(bytes[offset]) |
           (static_cast<std::uint32_t>(bytes[offset + 1]) << 8) |
           (static_cast<std::uint32_t>(bytes[offset + 2]) << 16) |
           (static_cast<std::uint32_t>(bytes[offset + 3]) << 24);
}

std::uint64_t u64(const std::vector<std::uint8_t>& bytes, std::size_t offset) {
    if (offset + 8 > bytes.size()) return 0;
    std::uint64_t value = 0;
    for (unsigned i = 0; i < 8; ++i) value |= static_cast<std::uint64_t>(bytes[offset + i]) << (i * 8);
    return value;
}

bool range_ok(std::size_t offset, std::size_t size, std::size_t total) {
    return offset <= total && size <= total - offset;
}

std::string section_name(const std::vector<std::uint8_t>& bytes, std::size_t offset) {
    std::string name;
    for (std::size_t i = 0; i < 8 && offset + i < bytes.size(); ++i) {
        if (bytes[offset + i] == 0) break;
        name.push_back(static_cast<char>(bytes[offset + i]));
    }
    return name;
}

} // namespace

bool PeImage::load_file(const std::string& path, std::string& error) {
    std::ifstream input(path, std::ios::binary | std::ios::ate);
    if (!input) {
        error = "unable to open file: " + path;
        return false;
    }
    const auto end = input.tellg();
    if (end <= 0) {
        error = "file is empty: " + path;
        return false;
    }
    std::vector<std::uint8_t> bytes(static_cast<std::size_t>(end));
    input.seekg(0, std::ios::beg);
    input.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    if (!input) {
        error = "unable to read file: " + path;
        return false;
    }
    return load_bytes(std::move(bytes), path, error);
}

bool PeImage::load_bytes(std::vector<std::uint8_t> bytes, std::string path, std::string& error) {
    bytes_ = std::move(bytes);
    info_ = {};
    info_.path = std::move(path);
    sections_.clear();
    imports_.clear();
    exports_.clear();
    runtime_functions_.clear();
    headers_size_ = 0;
    directory_count_ = 0;
    directories_.fill({0, 0});
    return parse(error);
}

bool PeImage::parse(std::string& error) {
    if (bytes_.size() < 0x40 || bytes_[0] != 'M' || bytes_[1] != 'Z') {
        error = "not a DOS/PE image (missing MZ header)";
        return false;
    }
    const std::uint32_t pe_offset = u32(bytes_, 0x3c);
    if (!range_ok(pe_offset, 24, bytes_.size()) || u32(bytes_, pe_offset) != 0x00004550) {
        error = "invalid PE signature";
        return false;
    }

    const std::size_t coff = pe_offset + 4;
    const std::uint16_t machine = u16(bytes_, coff);
    const std::uint16_t section_count = u16(bytes_, coff + 2);
    const std::uint16_t optional_size = u16(bytes_, coff + 16);
    const std::size_t optional = coff + 20;
    if (!range_ok(optional, optional_size, bytes_.size()) || section_count == 0 || section_count > 96) {
        error = "invalid PE optional header or section count";
        return false;
    }

    const std::uint16_t magic = u16(bytes_, optional);
    const bool pe32_plus = magic == 0x20b;
    const bool pe32 = magic == 0x10b;
    if (!pe32_plus && !pe32) {
        error = "unsupported PE optional header";
        return false;
    }
    info_.pe32_plus = pe32_plus;
    info_.architecture = machine == 0x8664 ? "x86-64" : machine == 0x14c ? "x86" : "unknown";
    info_.entry_rva = u32(bytes_, optional + 16);
    info_.image_base = pe32_plus ? u64(bytes_, optional + 24) : u32(bytes_, optional + 28);
    info_.image_size = u32(bytes_, optional + 56);
    info_.entry_point = info_.image_base + info_.entry_rva;
    headers_size_ = u32(bytes_, optional + 60);
    directory_count_ = pe32_plus ? u32(bytes_, optional + 108) : u32(bytes_, optional + 92);
    directory_count_ = std::min<std::uint32_t>(directory_count_, directories_.size());
    const std::size_t directory_base = optional + (pe32_plus ? 112 : 96);
    for (std::uint32_t i = 0; i < directory_count_; ++i) {
        directories_[i] = {u32(bytes_, directory_base + i * 8), u32(bytes_, directory_base + i * 8 + 4)};
    }

    const std::size_t section_table = optional + optional_size;
    if (!range_ok(section_table, static_cast<std::size_t>(section_count) * 40, bytes_.size())) {
        error = "truncated PE section table";
        return false;
    }
    sections_.reserve(section_count);
    for (std::uint16_t i = 0; i < section_count; ++i) {
        const std::size_t header = section_table + static_cast<std::size_t>(i) * 40;
        Section section;
        section.name = section_name(bytes_, header);
        section.virtual_size = u32(bytes_, header + 8);
        section.rva = u32(bytes_, header + 12);
        section.raw_size = u32(bytes_, header + 16);
        section.raw_offset = u32(bytes_, header + 20);
        section.characteristics = u32(bytes_, header + 36);
        section.start = info_.image_base + section.rva;
        section.end = section.start + std::max(section.virtual_size, section.raw_size);
        section.executable = (section.characteristics & 0x20000000u) != 0;
        section.readable = (section.characteristics & 0x40000000u) != 0;
        section.writable = (section.characteristics & 0x80000000u) != 0;
        if (range_ok(section.raw_offset, section.raw_size, bytes_.size())) {
            section.bytes.assign(bytes_.begin() + section.raw_offset,
                                 bytes_.begin() + section.raw_offset + section.raw_size);
        }
        sections_.push_back(std::move(section));
    }

    std::string ignored;
    if (directory_count_ > 0) parse_exports(directories_[0].first, directories_[0].second, ignored);
    if (directory_count_ > 1) parse_imports(directories_[1].first, directories_[1].second, ignored);
    if (directory_count_ > 3) parse_runtime_functions(directories_[3].first, directories_[3].second, ignored);
    return true;
}

std::optional<std::uint32_t> PeImage::rva_to_file_offset(std::uint32_t rva) const {
    if (rva < headers_size_ && rva < bytes_.size()) return rva;
    for (const auto& section : sections_) {
        const std::uint32_t span = std::max(section.virtual_size, section.raw_size);
        if (rva < section.rva || rva - section.rva >= span) continue;
        const std::uint64_t offset = static_cast<std::uint64_t>(section.raw_offset) + (rva - section.rva);
        if (offset < bytes_.size()) return static_cast<std::uint32_t>(offset);
        return std::nullopt;
    }
    return std::nullopt;
}

const Section* PeImage::section_for_rva(std::uint32_t rva) const {
    for (const auto& section : sections_) {
        const std::uint32_t span = std::max(section.virtual_size, section.raw_size);
        if (rva >= section.rva && rva - section.rva < span) return &section;
    }
    return nullptr;
}

const Section* PeImage::section_for_address(Address address) const {
    if (address < info_.image_base) return nullptr;
    const auto rva = address - info_.image_base;
    if (rva > std::numeric_limits<std::uint32_t>::max()) return nullptr;
    return section_for_rva(static_cast<std::uint32_t>(rva));
}

std::string PeImage::read_c_string_rva(std::uint32_t rva) const {
    const auto offset = rva_to_file_offset(rva);
    if (!offset) return {};
    std::string result;
    for (std::size_t i = *offset; i < bytes_.size() && result.size() < 4096; ++i) {
        const auto c = bytes_[i];
        if (c == 0) break;
        if (c < 0x20 && c != '\t') break;
        result.push_back(static_cast<char>(c));
    }
    return result;
}

bool PeImage::parse_imports(std::uint32_t directory_rva, std::uint32_t, std::string&) {
    if (directory_rva == 0) return true;
    const auto directory = rva_to_file_offset(directory_rva);
    if (!directory) return false;
    const std::size_t thunk_width = info_.pe32_plus ? 8 : 4;
    const std::uint64_t ordinal_mask = info_.pe32_plus ? 0x8000000000000000ull : 0x80000000ull;
    for (std::size_t descriptor = *directory; range_ok(descriptor, 20, bytes_.size()); descriptor += 20) {
        const std::uint32_t original_thunk = u32(bytes_, descriptor);
        const std::uint32_t name_rva = u32(bytes_, descriptor + 12);
        const std::uint32_t first_thunk = u32(bytes_, descriptor + 16);
        if (original_thunk == 0 && name_rva == 0 && first_thunk == 0) break;
        const std::string library = read_c_string_rva(name_rva);
        const std::uint32_t thunk_rva = original_thunk ? original_thunk : first_thunk;
        const auto thunk_offset = rva_to_file_offset(thunk_rva);
        if (!thunk_offset) continue;
        for (std::size_t index = 0; index < 1'000'000 &&
                                    range_ok(*thunk_offset + index * thunk_width, thunk_width, bytes_.size()); ++index) {
            const std::size_t item = *thunk_offset + index * thunk_width;
            const std::uint64_t value = info_.pe32_plus ? u64(bytes_, item) : u32(bytes_, item);
            if (value == 0) break;
            ImportSymbol symbol;
            symbol.library = library;
            symbol.thunk = info_.image_base + first_thunk + static_cast<Address>(index * thunk_width);
            symbol.by_ordinal = (value & ordinal_mask) != 0;
            if (symbol.by_ordinal) {
                symbol.ordinal = static_cast<std::uint16_t>(value & 0xffffu);
                symbol.name = "#" + std::to_string(symbol.ordinal);
            } else {
                const auto hint_name = rva_to_file_offset(static_cast<std::uint32_t>(value & 0x7fffffff));
                symbol.name = hint_name && *hint_name + 2 < bytes_.size()
                    ? read_c_string_rva(static_cast<std::uint32_t>(value & 0x7fffffff) + 2)
                    : "<invalid>";
            }
            imports_.push_back(std::move(symbol));
        }
    }
    return true;
}

bool PeImage::parse_exports(std::uint32_t directory_rva, std::uint32_t directory_size, std::string&) {
    if (directory_rva == 0) return true;
    const auto directory = rva_to_file_offset(directory_rva);
    if (!directory || !range_ok(*directory, 40, bytes_.size())) return false;
    const std::uint32_t ordinal_base = u32(bytes_, *directory + 16);
    const std::uint32_t function_count = u32(bytes_, *directory + 20);
    const std::uint32_t name_count = u32(bytes_, *directory + 24);
    const std::uint32_t functions_rva = u32(bytes_, *directory + 28);
    const std::uint32_t names_rva = u32(bytes_, *directory + 32);
    const std::uint32_t ordinals_rva = u32(bytes_, *directory + 36);
    const auto functions = rva_to_file_offset(functions_rva);
    const auto names = rva_to_file_offset(names_rva);
    const auto ordinals = rva_to_file_offset(ordinals_rva);
    if (!functions || !names || !ordinals) return false;
    for (std::uint32_t i = 0; i < name_count; ++i) {
        if (!range_ok(*names + static_cast<std::size_t>(i) * 4, 4, bytes_.size()) ||
            !range_ok(*ordinals + static_cast<std::size_t>(i) * 2, 2, bytes_.size())) break;
        const auto name = read_c_string_rva(u32(bytes_, *names + static_cast<std::size_t>(i) * 4));
        const std::uint32_t function_index = u16(bytes_, *ordinals + static_cast<std::size_t>(i) * 2);
        if (function_index >= function_count ||
            !range_ok(*functions + static_cast<std::size_t>(function_index) * 4, 4, bytes_.size())) continue;
        ExportSymbol symbol;
        symbol.name = name;
        symbol.ordinal = ordinal_base + function_index;
        const std::uint32_t function_rva = u32(bytes_, *functions + static_cast<std::size_t>(function_index) * 4);
        symbol.address = info_.image_base + function_rva;
        symbol.forwarded = function_rva >= directory_rva && function_rva < directory_rva + directory_size;
        exports_.push_back(std::move(symbol));
    }
    return true;
}

bool PeImage::parse_runtime_functions(std::uint32_t directory_rva, std::uint32_t directory_size, std::string&) {
    if (directory_rva == 0 || directory_size < 12) return true;
    const auto directory = rva_to_file_offset(directory_rva);
    if (!directory) return false;
    const auto available = std::min<std::size_t>(directory_size, bytes_.size() - std::min<std::size_t>(*directory, bytes_.size()));
    const auto count = available / 12;
    runtime_functions_.reserve(count);
    for (std::size_t index = 0; index < count; ++index) {
        const auto entry = *directory + index * 12;
        if (!range_ok(entry, 12, bytes_.size())) break;
        const auto begin_rva = u32(bytes_, entry);
        const auto end_rva = u32(bytes_, entry + 4);
        const auto unwind_rva = u32(bytes_, entry + 8);
        if (begin_rva >= end_rva) continue;
        const auto* begin_section = section_for_rva(begin_rva);
        const auto* end_section = section_for_rva(end_rva - 1);
        if (!begin_section || begin_section != end_section || !begin_section->executable) continue;
        runtime_functions_.push_back(RuntimeFunction{
            info_.image_base + begin_rva,
            info_.image_base + end_rva,
            unwind_rva ? info_.image_base + unwind_rva : 0,
        });
    }
    std::sort(runtime_functions_.begin(), runtime_functions_.end(), [](const RuntimeFunction& a, const RuntimeFunction& b) {
        return a.start < b.start;
    });
    runtime_functions_.erase(std::unique(runtime_functions_.begin(), runtime_functions_.end(), [](const RuntimeFunction& a, const RuntimeFunction& b) {
        return a.start == b.start && a.end == b.end;
    }), runtime_functions_.end());
    return true;
}

} // namespace paper

