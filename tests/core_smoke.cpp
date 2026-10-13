#include "paper/core/x86_decoder.hpp"
#include "paper/json.hpp"

#include <cassert>
#include <cstdint>
#include <vector>

int main() {
    paper::Json request = paper::Json::parse(R"({"method":"tools/call","id":7,"params":{"name":"xrefs_to"}})");
    assert(request.find("method") && request.find("method")->as_string() == "tools/call");
    assert(request.find("id") && request.find("id")->as_u64() == 7);

    paper::X86Decoder decoder;
    const std::vector<std::uint8_t> bytes{0x55, 0x48, 0x89, 0xe5, 0xe8, 0x05, 0x00, 0x00, 0x00, 0xc3};
    const auto first = decoder.decode(0x140001000, bytes);
    assert(first.length == 1 && first.mnemonic == "push");
    const auto call = decoder.decode(0x140001004, std::span<const std::uint8_t>(bytes.data() + 4, bytes.size() - 4));
    assert(call.kind == paper::InstructionKind::Call);
    assert(call.target && *call.target == 0x14000100e);
    const auto ret = decoder.decode(0x140001009, std::span<const std::uint8_t>(bytes.data() + 9, 1));
    assert(ret.kind == paper::InstructionKind::Return);
    const std::vector<std::uint8_t> import_call_bytes{0xff, 0x15, 0x34, 0x12, 0x00, 0x00};
    const auto import_call = decoder.decode(0x140001000, import_call_bytes);
    assert(import_call.kind == paper::InstructionKind::IndirectCall);
    assert(import_call.rip_relative);
    assert(import_call.target && *import_call.target == 0x14000223aull);
    const std::vector<std::uint8_t> stack_adjust{0x48, 0x83, 0xec, 0x20};
    const auto adjust = decoder.decode(0x140001000, stack_adjust);
    assert(adjust.mnemonic == "sub");
    assert(adjust.destination_register == "rsp");
    assert(adjust.immediate && *adjust.immediate == 0x20);
    const std::vector<std::uint8_t> switch_jump{0xff, 0x24, 0xc5, 0xd8, 0x52, 0x1e, 0x14};
    const auto indirect_jump = decoder.decode(0x140001000, switch_jump);
    assert(indirect_jump.kind == paper::InstructionKind::IndirectJump);
    assert(indirect_jump.memory_index == "rax");
    assert(indirect_jump.memory_scale == 8);
    assert(indirect_jump.target && *indirect_jump.target == 0x141e52d8ull);
    return 0;
}

