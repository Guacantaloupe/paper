#pragma once

#include "guapseudo/bitvector.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace guapseudo {

enum class ImageFormat {
    Raw,
    Elf64,
    Pe32Plus
};

enum class DecoderBackend {
    Builtin,
    Objdump,
    Auto
};

enum class InstructionKind {
    Unknown,
    Nop,
    Prologue,
    Epilogue,
    Move,
    LoadAddress,
    Arithmetic,
    Compare,
    Test,
    Call,
    Jump,
    ConditionalJump,
    Return,
    System,
    Trap
};

enum class ExpressionKind {
    Unknown,
    Constant,
    Variable,
    Unary,
    Binary,
    Load,
    Call
};

enum class ValueType {
    Unknown,
    Void,
    Bool,
    Int8,
    Int16,
    Int32,
    Int64,
    Pointer,
    FunctionPointer
};

struct Instruction {
    std::uint64_t address = 0;
    std::uint8_t size = 1;
    InstructionKind kind = InstructionKind::Unknown;
    std::string mnemonic;
    std::string operands;
    std::string pseudo;
    std::uint64_t target = 0;
    bool has_target = false;
    bool conditional = false;
    std::optional<BitVector> constant_value;
    // Normalized semantic metadata. The textual pseudo field remains useful
    // for diagnostics, while these fields drive SSA and expression folding.
    std::vector<std::string> read_operands;
    std::vector<std::string> write_operands;
    std::optional<std::int32_t> stack_offset;
    bool reads_memory = false;
    bool writes_memory = false;
    std::uint8_t operand_width = 64;
    std::vector<std::uint64_t> indirect_targets;
    bool is_switch_dispatch = false;
    std::string switch_expression;
};

struct BasicBlock {
    std::uint32_t id = 0;
    std::uint64_t address = 0;
    std::vector<Instruction> instructions;
    std::vector<std::uint32_t> successors;
    std::vector<std::uint32_t> predecessors;
    bool loop_header = false;
};

struct ControlFlowGraph {
    std::vector<BasicBlock> blocks;
    std::uint32_t entry = 0;
    std::vector<std::vector<std::uint32_t>> dominators;
};

enum class ControlFlowRegionKind {
    Linear,
    If,
    IfElse,
    While,
    DoWhile,
    Switch,
    Irreducible
};

struct ControlFlowRegion {
    ControlFlowRegionKind kind = ControlFlowRegionKind::Linear;
    std::uint32_t header = 0;
    std::uint32_t follow = 0;
    std::vector<std::uint32_t> body;
    std::vector<std::uint32_t> alternate;
    std::vector<std::pair<BitVector, std::uint32_t>> switch_cases;
    bool safe_to_render = false;
    bool invert_condition = false;
    std::string switch_expression;
};

struct ControlFlowStructure {
    std::vector<ControlFlowRegion> regions;
    bool has_irreducible_region = false;
};

struct SsaPhi {
    std::string variable;
    std::string result;
    ValueType type = ValueType::Unknown;
    std::vector<std::pair<std::uint32_t, std::string>> incoming;
};

struct SsaStatement {
    std::uint32_t block = 0;
    std::uint64_t address = 0;
    std::string result;
    std::string operation;
    std::vector<std::string> arguments;
    ValueType type = ValueType::Unknown;
    std::optional<BitVector> constant_value;
    std::string location;
    std::string expression;
    std::uint32_t expression_id = 0;
};

struct ExpressionNode {
    std::uint32_t id = 0;
    ExpressionKind kind = ExpressionKind::Unknown;
    std::string operation;
    std::vector<std::uint32_t> operands;
    std::string atom;
    std::optional<BitVector> constant_value;
};

struct SsaFunction {
    std::vector<std::vector<SsaPhi>> phis;
    std::vector<SsaStatement> statements;
    std::vector<std::pair<std::string, ValueType>> recovered_types;
    std::vector<ExpressionNode> expressions;
    std::vector<std::string> stack_slots;
};

struct FunctionSignature {
    std::string return_type = "undefined8";
    std::string calling_convention = "unknown";
    std::vector<std::pair<std::string, ValueType>> parameters;
    std::vector<std::string> locals;
    unsigned confidence = 0;
};

struct BinaryImage {
    ImageFormat format = ImageFormat::Raw;
    std::string source_name;
    std::uint64_t code_base = 0x1000;
    std::uint64_t entry = 0x1000;
    std::vector<std::uint8_t> code;

    std::uint64_t code_end() const { return code_base + code.size(); }
    bool contains(std::uint64_t address) const {
        return address >= code_base && address < code_end();
    }
    std::size_t offset_of(std::uint64_t address) const {
        return static_cast<std::size_t>(address - code_base);
    }
};

struct Function {
    std::uint64_t address = 0;
    std::string name;
    std::vector<Instruction> instructions;
    std::vector<std::uint64_t> basic_block_starts;
    ControlFlowGraph cfg;
    ControlFlowStructure control_flow;
    SsaFunction ssa;
    FunctionSignature signature;
};

struct AnalysisConfig {
    unsigned thread_count = 0;
    std::size_t max_function_bytes = 4096;
    bool show_stats = false;
    DecoderBackend decoder_backend = DecoderBackend::Auto;
};

struct AnalysisResult {
    std::vector<Function> functions;
    std::size_t decoded_instructions = 0;
    unsigned worker_count = 1;
    DecoderBackend decoder_backend = DecoderBackend::Builtin;
};

} // namespace guapseudo

