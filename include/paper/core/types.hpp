#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace paper {

using Address = std::uint64_t;

enum class XrefKind { Call, Jump, ConditionalJump, Data, Fallthrough };

enum class InstructionKind {
    Normal,
    Call,
    Jump,
    ConditionalJump,
    Return,
    IndirectCall,
    IndirectJump,
    Trap,
    Data,
};

struct Section {
    std::string name;
    std::uint32_t rva = 0;
    std::uint32_t virtual_size = 0;
    std::uint32_t raw_offset = 0;
    std::uint32_t raw_size = 0;
    std::uint32_t characteristics = 0;
    Address start = 0;
    Address end = 0;
    bool executable = false;
    bool readable = false;
    bool writable = false;
    std::vector<std::uint8_t> bytes;
};

struct ImportSymbol {
    std::string library;
    std::string name;
    std::uint16_t ordinal = 0;
    Address thunk = 0;
    bool by_ordinal = false;
};

struct ExportSymbol {
    std::string name;
    std::uint32_t ordinal = 0;
    Address address = 0;
    bool forwarded = false;
};

// PE exception/unwind metadata gives a strong function boundary on x64.
// It is optional because many small or stripped images do not carry it.
struct RuntimeFunction {
    Address start = 0;
    Address end = 0;
    Address unwind = 0;
};

struct Instruction {
    Address address = 0;
    std::uint8_t length = 1;
    std::array<std::uint8_t, 16> bytes{};
    std::uint8_t byte_count = 0;
    std::string mnemonic;
    std::string operands;
    InstructionKind kind = InstructionKind::Normal;
    std::optional<Address> target;
    bool target_indirect = false;
    bool rip_relative = false;
};

struct Xref {
    Address from = 0;
    Address to = 0;
    XrefKind kind = XrefKind::Data;
    std::string symbol;
};

struct BasicBlock {
    Address start = 0;
    Address end = 0;
    std::vector<Address> successors;
    std::vector<Address> predecessors;
};

struct Function {
    Address start = 0;
    Address end = 0;
    std::string name;
    bool exported = false;
    bool thunk = false;
    std::vector<Address> blocks;
};

struct AnalysisStats {
    std::uint64_t file_size = 0;
    std::uint64_t executable_bytes = 0;
    std::uint64_t instruction_count = 0;
    std::uint64_t function_count = 0;
    std::uint64_t basic_block_count = 0;
    std::uint64_t xref_count = 0;
    std::uint64_t worker_count = 0;
    std::uint64_t analysis_millis = 0;
};

struct ModuleInfo {
    std::string path;
    std::string format = "PE";
    std::string architecture;
    Address image_base = 0;
    Address entry_point = 0;
    std::uint32_t entry_rva = 0;
    std::uint32_t image_size = 0;
    bool pe32_plus = false;
};

inline std::string_view to_string(InstructionKind kind) {
    switch (kind) {
    case InstructionKind::Call: return "call";
    case InstructionKind::Jump: return "jump";
    case InstructionKind::ConditionalJump: return "conditional_jump";
    case InstructionKind::Return: return "return";
    case InstructionKind::IndirectCall: return "indirect_call";
    case InstructionKind::IndirectJump: return "indirect_jump";
    case InstructionKind::Trap: return "trap";
    case InstructionKind::Data: return "data";
    default: return "normal";
    }
}

inline std::string_view to_string(XrefKind kind) {
    switch (kind) {
    case XrefKind::Call: return "call";
    case XrefKind::Jump: return "jump";
    case XrefKind::ConditionalJump: return "conditional_jump";
    case XrefKind::Fallthrough: return "fallthrough";
    default: return "data";
    }
}

} // namespace paper

