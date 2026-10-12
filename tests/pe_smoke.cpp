#include "paper/core/pe_image.hpp"

#include <cassert>
#include <cstring>
#include <string>
#include <vector>

namespace {

void put16(std::vector<std::uint8_t>& bytes, std::size_t offset, std::uint16_t value) {
    bytes[offset] = static_cast<std::uint8_t>(value);
    bytes[offset + 1] = static_cast<std::uint8_t>(value >> 8);
}

void put32(std::vector<std::uint8_t>& bytes, std::size_t offset, std::uint32_t value) {
    for (unsigned i = 0; i < 4; ++i) bytes[offset + i] = static_cast<std::uint8_t>(value >> (i * 8));
}

void put64(std::vector<std::uint8_t>& bytes, std::size_t offset, std::uint64_t value) {
    for (unsigned i = 0; i < 8; ++i) bytes[offset + i] = static_cast<std::uint8_t>(value >> (i * 8));
}

} // namespace

int main() {
    std::vector<std::uint8_t> bytes(0x600, 0);
    bytes[0] = 'M'; bytes[1] = 'Z';
    put32(bytes, 0x3c, 0x80);
    std::memcpy(bytes.data() + 0x80, "PE\0\0", 4);
    put16(bytes, 0x84, 0x8664);
    put16(bytes, 0x86, 2);
    put16(bytes, 0x94, 0xf0);
    const std::size_t optional = 0x98;
    put16(bytes, optional, 0x20b);
    put32(bytes, optional + 16, 0x1000);
    put64(bytes, optional + 24, 0x140000000ull);
    put32(bytes, optional + 32, 0x1000);
    put32(bytes, optional + 36, 0x200);
    put32(bytes, optional + 56, 0x3000);
    put32(bytes, optional + 60, 0x200);
    put32(bytes, optional + 108, 16);
    // IMAGE_DIRECTORY_ENTRY_EXCEPTION (.pdata) points at one x64 runtime-function record.
    put32(bytes, optional + 112 + 3 * 8, 0x2000);
    put32(bytes, optional + 112 + 3 * 8 + 4, 12);
    const std::size_t sections = optional + 0xf0;
    std::memcpy(bytes.data() + sections, ".text", 5);
    put32(bytes, sections + 8, 0x200); put32(bytes, sections + 12, 0x1000);
    put32(bytes, sections + 16, 0x200); put32(bytes, sections + 20, 0x200);
    put32(bytes, sections + 36, 0x60000020);
    std::memcpy(bytes.data() + sections + 40, ".rdata", 6);
    put32(bytes, sections + 48, 0x200); put32(bytes, sections + 52, 0x2000);
    put32(bytes, sections + 56, 0x200); put32(bytes, sections + 60, 0x400);
    put32(bytes, sections + 76, 0x40000040);
    bytes[0x200] = 0x55; bytes[0x201] = 0xc3;
    put32(bytes, 0x400, 0x1000);
    put32(bytes, 0x404, 0x1002);
    put32(bytes, 0x408, 0x2008);

    paper::PeImage image;
    std::string error;
    assert(image.load_bytes(std::move(bytes), "fixture.exe", error));
    assert(error.empty());
    assert(image.info().architecture == "x86-64");
    assert(image.info().entry_point == 0x140001000ull);
    assert(image.sections().size() == 2);
    assert(image.sections()[0].executable);
    assert(image.rva_to_file_offset(0x1000).value() == 0x200);
    assert(image.runtime_functions().size() == 1);
    assert(image.runtime_functions().front().start == 0x140001000ull);
    assert(image.runtime_functions().front().end == 0x140001002ull);
    return 0;
}

