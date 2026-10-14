#include "paper/core/pe_image.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <fstream>
#include <functional>
#include <iomanip>
#include <limits>
#include <sstream>

namespace paper {
namespace {

// Small dependency-free SHA-256 implementation. Paper is built as a single
// portable core library on MSVC and on the Linux smoke-test host, so pulling
// OpenSSL in just for file identity would make the Windows build needlessly
// fragile. The input is intentionally a byte range, not a C string.
class Sha256 {
public:
    Sha256() { reset(); }

    void reset() {
        state_ = {0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
                  0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u};
        buffer_size_ = 0;
        bit_count_ = 0;
    }

    void update(const std::uint8_t* data, std::size_t size) {
        if (!data || size == 0) return;
        bit_count_ += static_cast<std::uint64_t>(size) * 8u;
        while (size != 0) {
            const auto take = std::min<std::size_t>(size, 64 - buffer_size_);
            std::memcpy(buffer_.data() + buffer_size_, data, take);
            buffer_size_ += take;
            data += take;
            size -= take;
            if (buffer_size_ == 64) {
                transform(buffer_.data());
                buffer_size_ = 0;
            }
        }
    }

    std::string finish() const {
        Sha256 copy = *this;
        copy.buffer_[copy.buffer_size_++] = 0x80;
        if (copy.buffer_size_ > 56) {
            while (copy.buffer_size_ < 64) copy.buffer_[copy.buffer_size_++] = 0;
            copy.transform(copy.buffer_.data());
            copy.buffer_size_ = 0;
        }
        while (copy.buffer_size_ < 56) copy.buffer_[copy.buffer_size_++] = 0;
        for (int shift = 56; shift >= 0; shift -= 8)
            copy.buffer_[copy.buffer_size_++] = static_cast<std::uint8_t>(copy.bit_count_ >> shift);
        copy.transform(copy.buffer_.data());

        static constexpr char digits[] = "0123456789abcdef";
        std::string result;
        result.resize(64);
        for (std::size_t i = 0; i < copy.state_.size(); ++i) {
            for (unsigned byte = 0; byte < 4; ++byte) {
                const auto value = static_cast<std::uint8_t>(copy.state_[i] >> (24 - byte * 8));
                result[(i * 4 + byte) * 2] = digits[value >> 4];
                result[(i * 4 + byte) * 2 + 1] = digits[value & 0xf];
            }
        }
        return result;
    }

private:
    static constexpr std::array<std::uint32_t, 64> round_constants_ = {
        0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u,
        0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
        0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
        0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
        0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
        0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
        0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
        0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
        0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
        0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
        0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u,
        0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
        0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u,
        0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
        0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
        0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u};

    static std::uint32_t rotate_right(std::uint32_t value, unsigned amount) {
        return (value >> amount) | (value << (32 - amount));
    }

    void transform(const std::uint8_t* block) {
        std::array<std::uint32_t, 64> schedule{};
        for (unsigned i = 0; i < 16; ++i) {
            schedule[i] = (static_cast<std::uint32_t>(block[i * 4]) << 24) |
                          (static_cast<std::uint32_t>(block[i * 4 + 1]) << 16) |
                          (static_cast<std::uint32_t>(block[i * 4 + 2]) << 8) |
                          static_cast<std::uint32_t>(block[i * 4 + 3]);
        }
        for (unsigned i = 16; i < 64; ++i) {
            const auto s0 = rotate_right(schedule[i - 15], 7) ^ rotate_right(schedule[i - 15], 18) ^ (schedule[i - 15] >> 3);
            const auto s1 = rotate_right(schedule[i - 2], 17) ^ rotate_right(schedule[i - 2], 19) ^ (schedule[i - 2] >> 10);
            schedule[i] = schedule[i - 16] + s0 + schedule[i - 7] + s1;
        }
        auto a = state_[0]; auto b = state_[1]; auto c = state_[2]; auto d = state_[3];
        auto e = state_[4]; auto f = state_[5]; auto g = state_[6]; auto h = state_[7];
        for (unsigned i = 0; i < 64; ++i) {
            const auto s1 = rotate_right(e, 6) ^ rotate_right(e, 11) ^ rotate_right(e, 25);
            const auto choose = (e & f) ^ ((~e) & g);
            const auto temp1 = h + s1 + choose + round_constants_[i] + schedule[i];
            const auto s0 = rotate_right(a, 2) ^ rotate_right(a, 13) ^ rotate_right(a, 22);
            const auto majority = (a & b) ^ (a & c) ^ (b & c);
            const auto temp2 = s0 + majority;
            h = g; g = f; f = e; e = d + temp1;
            d = c; c = b; b = a; a = temp1 + temp2;
        }
        state_[0] += a; state_[1] += b; state_[2] += c; state_[3] += d;
        state_[4] += e; state_[5] += f; state_[6] += g; state_[7] += h;
    }

    std::array<std::uint32_t, 8> state_{};
    std::array<std::uint8_t, 64> buffer_{};
    std::size_t buffer_size_ = 0;
    std::uint64_t bit_count_ = 0;
};

std::string sha256_bytes(const std::uint8_t* data, std::size_t size) {
    Sha256 hash;
    hash.update(data, size);
    return hash.finish();
}

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

std::string PeImage::sha256(const std::uint8_t* data, std::size_t size) {
    return sha256_bytes(data, size);
}

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
    tls_callbacks_.clear();
    relocations_.clear();
    resources_.clear();
    pdb_info_ = {};
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
    directory_count_ = std::min<std::uint32_t>(
        directory_count_, static_cast<std::uint32_t>(directories_.size()));
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
    if (directory_count_ > 2) parse_resources(directories_[2].first, directories_[2].second, ignored);
    if (directory_count_ > 3) parse_runtime_functions(directories_[3].first, directories_[3].second, ignored);
    if (directory_count_ > 5) parse_relocations(directories_[5].first, directories_[5].second, ignored);
    if (directory_count_ > 6) parse_debug(directories_[6].first, directories_[6].second, ignored);
    if (directory_count_ > 9) parse_tls(directories_[9].first, directories_[9].second, ignored);

    // Identity is computed after the PE has been validated and section
    // boundaries are known.  The full hash covers the exact on-disk bytes;
    // the text hash covers executable section raw bytes in PE order; the
    // pdata hash covers only the raw exception-directory range.  Keeping
    // these separate lets a client distinguish a byte-for-byte replacement
    // from a code-only or unwind-only rebuild without relying on timestamps.
    info_.sha256 = sha256_bytes(bytes_.data(), bytes_.size());
    Sha256 text_hash;
    bool saw_text = false;
    for (const auto& section : sections_) {
        if (!section.executable || section.bytes.empty()) continue;
        text_hash.update(section.bytes.data(), section.bytes.size());
        saw_text = true;
    }
    info_.text_sha256 = saw_text ? text_hash.finish() : std::string{};
    if (directory_count_ > 3 && directories_[3].first != 0 && directories_[3].second != 0) {
        const auto pdata_offset = rva_to_file_offset(directories_[3].first);
        if (pdata_offset && *pdata_offset < bytes_.size()) {
            const auto count = std::min<std::size_t>(directories_[3].second, bytes_.size() - *pdata_offset);
            info_.pdata_sha256 = sha256_bytes(bytes_.data() + *pdata_offset, count);
        }
    }
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
            symbol.descriptor = info_.image_base + directory_rva + static_cast<Address>(descriptor - *directory);
            symbol.original_first_thunk = original_thunk;
            symbol.first_thunk = first_thunk;
            symbol.names_from_first_thunk = original_thunk == 0;
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
        if (symbol.forwarded) symbol.forwarder = read_c_string_rva(function_rva);
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
        RuntimeFunction record;
        record.start = info_.image_base + begin_rva;
        record.end = info_.image_base + end_rva;
        record.unwind = unwind_rva ? info_.image_base + unwind_rva : 0;
        if (unwind_rva) {
            const auto unwind_offset = rva_to_file_offset(unwind_rva);
            if (unwind_offset && range_ok(*unwind_offset, 4, bytes_.size())) {
                const auto version_flags = bytes_[*unwind_offset];
                record.unwind_flags = static_cast<std::uint8_t>(version_flags >> 3);
                record.unwind_code_count = bytes_[*unwind_offset + 2];
                const std::size_t codes_size = static_cast<std::size_t>(record.unwind_code_count) * 2;
                std::size_t handler_offset = 4 + ((codes_size + 3) & ~std::size_t(3));
                if ((record.unwind_flags & 0x3u) != 0 && range_ok(*unwind_offset + handler_offset, 4, bytes_.size())) {
                    const auto handler_rva = u32(bytes_, *unwind_offset + handler_offset);
                    record.exception_handler = handler_rva ? info_.image_base + handler_rva : 0;
                    // The language-specific payload starts immediately after
                    // the handler RVA.  It is deliberately kept bounded and
                    // file-backed; the analyzer validates any structure
                    // before presenting fields as MSVC EH facts.
                    const auto data_rva = static_cast<std::uint64_t>(unwind_rva) + handler_offset + 4;
                    if (data_rva <= 0xffffffffu) {
                        const auto data_offset = rva_to_file_offset(static_cast<std::uint32_t>(data_rva));
                        if (data_offset && *data_offset < bytes_.size()) {
                            record.handler_data = info_.image_base + data_rva;
                            const auto count_bytes = std::min<std::size_t>(64, bytes_.size() - *data_offset);
                            record.handler_data_bytes.assign(bytes_.begin() + static_cast<std::ptrdiff_t>(*data_offset),
                                                             bytes_.begin() + static_cast<std::ptrdiff_t>(*data_offset + count_bytes));
                        }
                    }
                }
            }
        }
        runtime_functions_.push_back(std::move(record));
    }
    std::sort(runtime_functions_.begin(), runtime_functions_.end(), [](const RuntimeFunction& a, const RuntimeFunction& b) {
        return a.start < b.start;
    });
    runtime_functions_.erase(std::unique(runtime_functions_.begin(), runtime_functions_.end(), [](const RuntimeFunction& a, const RuntimeFunction& b) {
        return a.start == b.start && a.end == b.end;
    }), runtime_functions_.end());
    return true;
}

bool PeImage::parse_tls(std::uint32_t directory_rva, std::uint32_t directory_size, std::string&) {
    if (directory_rva == 0 || directory_size == 0) return true;
    const auto directory = rva_to_file_offset(directory_rva);
    if (!directory) return false;
    const std::size_t width = info_.pe32_plus ? 8 : 4;
    const std::size_t callbacks_field = info_.pe32_plus ? 24 : 12;
    if (!range_ok(*directory, callbacks_field + width, bytes_.size())) return false;
    const Address callbacks_va = info_.pe32_plus ? u64(bytes_, *directory + callbacks_field)
                                                  : u32(bytes_, *directory + callbacks_field);
    if (callbacks_va == 0) return true;
    const auto callbacks_rva = callbacks_va >= info_.image_base
        ? callbacks_va - info_.image_base : callbacks_va;
    if (callbacks_rva > std::numeric_limits<std::uint32_t>::max()) return false;
    const auto callbacks = rva_to_file_offset(static_cast<std::uint32_t>(callbacks_rva));
    if (!callbacks) return false;
    for (std::size_t index = 0; index < 100'000 && range_ok(*callbacks + index * width, width, bytes_.size()); ++index) {
        const Address callback = info_.pe32_plus ? u64(bytes_, *callbacks + index * width)
                                                  : u32(bytes_, *callbacks + index * width);
        if (callback == 0) break;
        if (section_for_address(callback)) tls_callbacks_.push_back(TlsCallback{callback});
    }
    return true;
}

bool PeImage::parse_relocations(std::uint32_t directory_rva, std::uint32_t directory_size, std::string&) {
    if (directory_rva == 0 || directory_size < 8) return true;
    const auto directory = rva_to_file_offset(directory_rva);
    if (!directory || *directory >= bytes_.size()) return false;
    const auto end = std::min<std::size_t>(bytes_.size(), *directory + directory_size);
    std::size_t cursor = *directory;
    while (cursor + 8 <= end) {
        const auto page_rva = u32(bytes_, cursor);
        const auto block_size = u32(bytes_, cursor + 4);
        if (block_size < 8 || cursor + block_size > end) break;
        const std::size_t entry_count = (block_size - 8) / 2;
        for (std::size_t index = 0; index < entry_count; ++index) {
            const auto raw = u16(bytes_, cursor + 8 + index * 2);
            const auto type = static_cast<std::uint16_t>(raw >> 12);
            const auto offset = static_cast<std::uint16_t>(raw & 0x0fff);
            if (type == 0) continue; // IMAGE_REL_BASED_ABSOLUTE padding.
            const auto rva = static_cast<std::uint64_t>(page_rva) + offset;
            if (rva > std::numeric_limits<std::uint32_t>::max()) continue;
            const auto address = info_.image_base + rva;
            if (section_for_rva(static_cast<std::uint32_t>(rva))) {
                relocations_.push_back(RelocationEntry{address, page_rva, type});
            }
        }
        cursor += block_size;
    }
    std::sort(relocations_.begin(), relocations_.end(), [](const RelocationEntry& left, const RelocationEntry& right) {
        return left.address < right.address;
    });
    return true;
}

bool PeImage::parse_resources(std::uint32_t directory_rva, std::uint32_t directory_size, std::string&) {
    if (directory_rva == 0 || directory_size < 16) return true;
    const auto root = rva_to_file_offset(directory_rva);
    if (!root || !range_ok(*root, 16, bytes_.size())) return false;
    const auto limit = std::min<std::size_t>(bytes_.size(), *root + directory_size);
    auto name_for = [&](std::uint32_t raw) {
        if ((raw & 0x80000000u) == 0) {
            static const char* known[] = {"", "CURSOR", "BITMAP", "ICON", "MENU", "DIALOG", "STRING", "FONTDIR", "FONT", "ACCELERATOR", "RCDATA", "MESSAGETABLE", "GROUP_CURSOR", "", "GROUP_ICON", "", "VERSION", "DLGINCLUDE", "PLUGPLAY", "VXD", "ANICURSOR", "ANIICON", "HTML", "MANIFEST"};
            const auto id = raw & 0x7fffffffu;
            if (id < sizeof(known) / sizeof(known[0]) && known[id][0] != 0) return std::string(known[id]);
            return std::string("#") + std::to_string(id);
        }
        const auto offset = *root + (raw & 0x7fffffffu);
        if (!range_ok(offset, 2, limit)) return std::string("<invalid>");
        const auto length = u16(bytes_, offset);
        std::string value;
        value.reserve(length);
        for (std::size_t index = 0; index < length && offset + 2 + index * 2 + 1 < limit; ++index) {
            const auto code = u16(bytes_, offset + 2 + index * 2);
            value.push_back(code <= 0x7f ? static_cast<char>(code) : '?');
        }
        return value;
    };
    std::size_t record_count = 0;
    std::function<void(std::size_t, std::vector<std::string>&, unsigned)> visit;
    visit = [&](std::size_t directory_offset, std::vector<std::string>& path, unsigned depth) {
        if (depth > 8 || record_count >= 100'000 || !range_ok(directory_offset, 16, limit)) return;
        const auto named = u16(bytes_, directory_offset + 12);
        const auto ids = u16(bytes_, directory_offset + 14);
        const auto count = static_cast<std::size_t>(named) + ids;
        if (count > 65'535 || !range_ok(directory_offset + 16, count * 8, limit)) return;
        for (std::size_t index = 0; index < count && record_count < 100'000; ++index) {
            const auto entry = directory_offset + 16 + index * 8;
            const auto name = name_for(u32(bytes_, entry));
            const auto raw_offset = u32(bytes_, entry + 4);
            path.push_back(name);
            if (raw_offset & 0x80000000u) {
                const auto child = *root + (raw_offset & 0x7fffffffu);
                visit(child, path, depth + 1);
            } else {
                const auto data = *root + (raw_offset & 0x7fffffffu);
                if (range_ok(data, 16, limit)) {
                    ResourceEntry record;
                    if (!path.empty()) record.type = path[0];
                    if (path.size() > 1) record.name = path[1];
                    if (path.size() > 2) record.language = path[2];
                    record.data_rva = u32(bytes_, data);
                    record.size = u32(bytes_, data + 4);
                    record.codepage = u32(bytes_, data + 8);
                    resources_.push_back(std::move(record));
                    ++record_count;
                }
            }
            path.pop_back();
        }
    };
    std::vector<std::string> path;
    visit(*root, path, 0);
    return true;
}

bool PeImage::parse_debug(std::uint32_t directory_rva, std::uint32_t directory_size, std::string&) {
    if (directory_rva == 0 || directory_size < 28) return true;
    const auto directory = rva_to_file_offset(directory_rva);
    if (!directory || *directory >= bytes_.size()) return false;
    const auto count = std::min<std::size_t>(directory_size / 28, 4096);
    for (std::size_t index = 0; index < count; ++index) {
        const auto entry = *directory + index * 28;
        if (!range_ok(entry, 28, bytes_.size())) break;
        const auto type = u32(bytes_, entry + 12);
        const auto size = u32(bytes_, entry + 16);
        const auto data_rva = u32(bytes_, entry + 20);
        const auto data_file = u32(bytes_, entry + 24);
        if (type != 2 || size < 24) continue; // IMAGE_DEBUG_TYPE_CODEVIEW
        std::optional<std::size_t> data;
        if (data_file != 0 && range_ok(data_file, size, bytes_.size())) data = data_file;
        else if (const auto mapped = rva_to_file_offset(data_rva); mapped && range_ok(*mapped, size, bytes_.size())) data = *mapped;
        if (!data || u32(bytes_, *data) != 0x53445352u) continue; // RSDS
        pdb_info_.present = true;
        pdb_info_.debug_type = type;
        const auto d1 = u32(bytes_, *data + 4);
        const auto d2 = u16(bytes_, *data + 8);
        const auto d3 = u16(bytes_, *data + 10);
        std::ostringstream guid;
        guid << std::hex << std::setfill('0') << std::setw(8) << d1 << '-'
             << std::setw(4) << d2 << '-' << std::setw(4) << d3 << '-';
        for (std::size_t byte = 0; byte < 8; ++byte) {
            if (byte == 2) guid << '-';
            guid << std::setw(2) << static_cast<unsigned>(bytes_[*data + 12 + byte]);
        }
        pdb_info_.guid = guid.str();
        pdb_info_.age = u32(bytes_, *data + 20);
        std::size_t path = *data + 24;
        while (path < *data + size && path < bytes_.size() && bytes_[path] != 0) ++path;
        pdb_info_.path.assign(reinterpret_cast<const char*>(bytes_.data() + *data + 24), path - (*data + 24));
        break;
    }
    return true;
}

} // namespace paper

