#include "guapseudo/cfg.hpp"

#include <algorithm>
#include <iterator>
#include <limits>
#include <unordered_map>
#include <unordered_set>

namespace guapseudo {
namespace {

void add_unique(std::vector<std::uint32_t>& values, std::uint32_t value) {
    if (std::find(values.begin(), values.end(), value) == values.end()) values.push_back(value);
}

} // namespace

void ControlFlowAnalyzer::build(Function& function) {
    function.cfg = {};
    if (function.instructions.empty()) return;

    std::vector<std::uint64_t> starts;
    starts.push_back(function.address);
    for (const auto address : function.basic_block_starts) starts.push_back(address);
    for (const auto& instruction : function.instructions) {
        if ((instruction.kind == InstructionKind::Jump ||
             instruction.kind == InstructionKind::ConditionalJump) &&
            instruction.has_target) {
            starts.push_back(instruction.target);
            if (instruction.kind == InstructionKind::ConditionalJump) {
                starts.push_back(instruction.address + instruction.size);
            }
        }
    }

    std::unordered_map<std::uint64_t, std::size_t> instruction_index;
    for (std::size_t i = 0; i < function.instructions.size(); ++i) {
        instruction_index[function.instructions[i].address] = i;
    }
    std::sort(starts.begin(), starts.end());
    starts.erase(std::unique(starts.begin(), starts.end()), starts.end());
    starts.erase(std::remove_if(starts.begin(), starts.end(), [&](std::uint64_t address) {
                    return instruction_index.find(address) == instruction_index.end();
                }),
                starts.end());
    if (starts.empty()) return;

    std::unordered_map<std::uint64_t, std::uint32_t> block_by_address;
    for (std::uint32_t id = 0; id < starts.size(); ++id) {
        block_by_address[starts[id]] = id;
        BasicBlock block;
        block.id = id;
        block.address = starts[id];
        function.cfg.blocks.push_back(std::move(block));
    }
    function.cfg.entry = block_by_address[function.address];

    for (std::size_t id = 0; id < starts.size(); ++id) {
        const auto begin = instruction_index[starts[id]];
        const auto end = id + 1 < starts.size()
                             ? instruction_index[starts[id + 1]]
                             : function.instructions.size();
        auto& block = function.cfg.blocks[id];
        block.instructions.assign(function.instructions.begin() + static_cast<std::ptrdiff_t>(begin),
                                  function.instructions.begin() + static_cast<std::ptrdiff_t>(end));
    }

    for (std::size_t id = 0; id < function.cfg.blocks.size(); ++id) {
        auto& block = function.cfg.blocks[id];
        if (block.instructions.empty()) continue;
        const auto& last = block.instructions.back();
        if (last.kind == InstructionKind::ConditionalJump && last.has_target) {
            const auto target = block_by_address.find(last.target);
            if (target != block_by_address.end()) add_unique(block.successors, target->second);
            const auto fallthrough = block_by_address.find(last.address + last.size);
            if (fallthrough != block_by_address.end()) add_unique(block.successors, fallthrough->second);
        } else if (last.kind == InstructionKind::Jump && last.has_target) {
            const auto target = block_by_address.find(last.target);
            if (target != block_by_address.end()) add_unique(block.successors, target->second);
        } else if (last.kind == InstructionKind::Jump) {
            for (const auto target_address : last.indirect_targets) {
                const auto target = block_by_address.find(target_address);
                if (target != block_by_address.end()) add_unique(block.successors, target->second);
            }
        } else if (last.kind != InstructionKind::Return && id + 1 < function.cfg.blocks.size()) {
            add_unique(block.successors, static_cast<std::uint32_t>(id + 1));
        }
    }

    for (auto& block : function.cfg.blocks) {
        for (const auto successor : block.successors) {
            add_unique(function.cfg.blocks[successor].predecessors, block.id);
        }
    }

    const auto block_count = function.cfg.blocks.size();
    function.cfg.dominators.assign(block_count, std::vector<std::uint32_t>());
    for (std::size_t id = 0; id < block_count; ++id) {
        if (id == function.cfg.entry) {
            function.cfg.dominators[id].push_back(static_cast<std::uint32_t>(id));
        } else {
            for (std::size_t candidate = 0; candidate < block_count; ++candidate) {
                function.cfg.dominators[id].push_back(static_cast<std::uint32_t>(candidate));
            }
        }
    }

    bool changed = true;
    while (changed) {
        changed = false;
        for (std::size_t id = 0; id < block_count; ++id) {
            if (id == function.cfg.entry || function.cfg.blocks[id].predecessors.empty()) continue;
            std::vector<std::uint32_t> intersection;
            intersection = function.cfg.dominators[function.cfg.blocks[id].predecessors.front()];
            for (std::size_t p = 1; p < function.cfg.blocks[id].predecessors.size(); ++p) {
                const auto predecessor = function.cfg.blocks[id].predecessors[p];
                std::vector<std::uint32_t> next;
                std::set_intersection(intersection.begin(), intersection.end(),
                                      function.cfg.dominators[predecessor].begin(),
                                      function.cfg.dominators[predecessor].end(),
                                      std::back_inserter(next));
                intersection = std::move(next);
            }
            intersection.push_back(static_cast<std::uint32_t>(id));
            std::sort(intersection.begin(), intersection.end());
            if (intersection != function.cfg.dominators[id]) {
                function.cfg.dominators[id] = std::move(intersection);
                changed = true;
            }
        }
    }

    for (auto& block : function.cfg.blocks) {
        for (const auto successor : block.successors) {
            const auto& dominated = function.cfg.dominators[block.id];
            if (std::find(dominated.begin(), dominated.end(), successor) != dominated.end()) {
                function.cfg.blocks[successor].loop_header = true;
            }
        }
    }
}

} // namespace guapseudo

