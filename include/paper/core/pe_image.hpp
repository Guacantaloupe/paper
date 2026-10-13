#pragma once

#include "paper/core/types.hpp"

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace paper {

class PeImage {
public:
    bool load_file(const std::string& path, std::string& error);
    bool load_bytes(std::vector<std::uint8_t> bytes, std::string path, std::string& error);

    const ModuleInfo& info() const noexcept { return info_; }
    const std::vector<std::uint8_t>& bytes() const noexcept { return bytes_; }
    const std::vector<Section>& sections() const noexcept { return sections_; }
    const std::vector<ImportSymbol>& imports() const noexcept { return imports_; }
    const std::vector<ExportSymbol>& exports() const noexcept { return exports_; }
    const std::vector<RuntimeFunction>& runtime_functions() const noexcept { return runtime_functions_; }
    const std::vector<TlsCallback>& tls_callbacks() const noexcept { return tls_callbacks_; }
    const std::vector<RelocationEntry>& relocations() const noexcept { return relocations_; }
    const std::vector<ResourceEntry>& resources() const noexcept { return resources_; }
    const PdbInfo& pdb_info() const noexcept { return pdb_info_; }

    std::optional<std::uint32_t> rva_to_file_offset(std::uint32_t rva) const;
    const Section* section_for_rva(std::uint32_t rva) const;
    const Section* section_for_address(Address address) const;

private:
    bool parse(std::string& error);
    bool parse_imports(std::uint32_t directory_rva, std::uint32_t directory_size, std::string& error);
    bool parse_exports(std::uint32_t directory_rva, std::uint32_t directory_size, std::string& error);
    bool parse_runtime_functions(std::uint32_t directory_rva, std::uint32_t directory_size, std::string& error);
    bool parse_tls(std::uint32_t directory_rva, std::uint32_t directory_size, std::string& error);
    bool parse_relocations(std::uint32_t directory_rva, std::uint32_t directory_size, std::string& error);
    bool parse_resources(std::uint32_t directory_rva, std::uint32_t directory_size, std::string& error);
    bool parse_debug(std::uint32_t directory_rva, std::uint32_t directory_size, std::string& error);
    std::string read_c_string_rva(std::uint32_t rva) const;

    ModuleInfo info_;
    std::vector<std::uint8_t> bytes_;
    std::vector<Section> sections_;
    std::vector<ImportSymbol> imports_;
    std::vector<ExportSymbol> exports_;
    std::vector<RuntimeFunction> runtime_functions_;
    std::vector<TlsCallback> tls_callbacks_;
    std::vector<RelocationEntry> relocations_;
    std::vector<ResourceEntry> resources_;
    PdbInfo pdb_info_;
    std::uint32_t headers_size_ = 0;
    std::uint32_t directory_count_ = 0;
    std::array<std::pair<std::uint32_t, std::uint32_t>, 16> directories_{};
};

} // namespace paper

