#include "guapseudo/structurer.hpp"

#include <algorithm>
#include <functional>
#include <limits>
#include <map>
#include <set>
#include <unordered_map>
#include <unordered_set>

namespace guapseudo {
namespace {

constexpr std::uint32_t no_block = std::numeric_limits<std::uint32_t>::max();

bool contains(const std::vector<std::uint32_t>& values, std::uint32_t value) {
    return std::find(values.begin(), values.end(), value) != values.end();
}

bool has_region(const ControlFlowStructure& structure, ControlFlowRegionKind kind,
               std::uint32_t header) {
    return std::any_of(structure.regions.begin(), structure.regions.end(),
                       [&](const ControlFlowRegion& region) {
                           return region.kind == kind && region.header == header;
                       });
}

void add_region(ControlFlowStructure& structure, ControlFlowRegion region) {
    if (!has_region(structure, region.kind, region.header)) {
        structure.regions.push_back(std::move(region));
    }
}

} // namespace

const char* control_flow_region_name(ControlFlowRegionKind kind) {
    switch (kind) {
    case ControlFlowRegionKind::Linear: return "linear";
    case ControlFlowRegionKind::If: return "if";
    case ControlFlowRegionKind::IfElse: return "if/else";
    case ControlFlowRegionKind::While: return "while";
    case ControlFlowRegionKind::DoWhile: return "do/while";
    case ControlFlowRegionKind::Switch: return "switch";
    case ControlFlowRegionKind::Irreducible: return "irreducible";
    }
    return "unknown";
}

void ControlFlowStructurer::run(Function& function) {
    function.control_flow = {};
    const auto& blocks = function.cfg.blocks;
    const auto count = blocks.size();
    if (count == 0) return;

    // Tarjan SCCs identify irreducible regions: a cyclic component with
    // multiple entries cannot be represented safely by one structured loop.
    std::vector<int> index(count, -1), lowlink(count, -1), stack;
    std::vector<bool> on_stack(count, false);
    int next_index = 0;
    std::function<void(std::uint32_t)> visit = [&](std::uint32_t node) {
        index[node] = lowlink[node] = next_index++;
        stack.push_back(static_cast<int>(node));
        on_stack[node] = true;
        for (const auto successor : blocks[node].successors) {
            if (index[successor] == -1) {
                visit(successor);
                lowlink[node] = std::min(lowlink[node], lowlink[successor]);
            } else if (on_stack[successor]) {
                lowlink[node] = std::min(lowlink[node], index[successor]);
            }
        }
        if (lowlink[node] != index[node]) return;

        std::vector<std::uint32_t> component;
        for (;;) {
            const auto member = static_cast<std::uint32_t>(stack.back());
            stack.pop_back();
            on_stack[member] = false;
            component.push_back(member);
            if (member == node) break;
        }
        std::sort(component.begin(), component.end());
        bool cyclic = component.size() > 1;
        if (!cyclic && !component.empty()) cyclic = contains(blocks[component.front()].successors, component.front());
        if (!cyclic) return;

        std::unordered_set<std::uint32_t> members(component.begin(), component.end());
        std::set<std::uint32_t> entries;
        for (const auto member : component) {
            for (const auto predecessor : blocks[member].predecessors) {
                if (members.find(predecessor) == members.end()) entries.insert(member);
            }
        }
        if (entries.size() > 1) {
            ControlFlowRegion region;
            region.kind = ControlFlowRegionKind::Irreducible;
            region.header = component.front();
            region.body = std::move(component);
            add_region(function.control_flow, std::move(region));
            function.control_flow.has_irreducible_region = true;
        }
    };
    for (std::uint32_t node = 0; node < count; ++node) {
        if (index[node] == -1) visit(node);
    }

    // A back edge is an edge whose destination dominates its source. Build a
    // natural loop by walking predecessors back to the header.
    std::map<std::uint32_t, std::vector<std::uint32_t>> back_edges;
    for (const auto& block : blocks) {
        for (const auto successor : block.successors) {
            if (successor < function.cfg.dominators.size() &&
                contains(function.cfg.dominators[block.id], successor)) {
                back_edges[successor].push_back(block.id);
            }
        }
    }
    for (const auto& [header, tails] : back_edges) {
        std::set<std::uint32_t> body{header};
        std::vector<std::uint32_t> pending(tails.begin(), tails.end());
        while (!pending.empty()) {
            const auto node = pending.back();
            pending.pop_back();
            if (!body.insert(node).second) continue;
            for (const auto predecessor : blocks[node].predecessors) {
                if (predecessor != header) pending.push_back(predecessor);
            }
        }
        ControlFlowRegion region;
        region.kind = ControlFlowRegionKind::While;
        region.header = header;
        region.body.assign(body.begin(), body.end());
        for (const auto successor : blocks[header].successors) {
            if (!body.count(successor)) {
                region.follow = successor;
                break;
            }
        }
        if (blocks[header].instructions.size() > 0 && body.size() == 2 &&
            blocks[header].instructions.back().kind == InstructionKind::ConditionalJump &&
            region.follow != no_block) {
            region.safe_to_render = true;
            const auto& branch = blocks[header].instructions.back();
            const auto target = std::find_if(blocks[header].successors.begin(), blocks[header].successors.end(),
                                             [&](std::uint32_t id) { return blocks[id].address == branch.target; });
            if (target != blocks[header].successors.end() && *target == region.follow) {
                region.invert_condition = true;
            }
        }
        if (!has_region(function.control_flow, ControlFlowRegionKind::Irreducible, header)) {
            add_region(function.control_flow, std::move(region));
        }
    }

    // A fan-out is the compact representation used by the printer for a
    // switch/jump-table candidate. The actual case constants may be recovered
    // by a future indirect-jump value analysis; targets remain exact today.
    for (const auto& block : blocks) {
        const auto switch_dispatch = !block.instructions.empty() && block.instructions.back().is_switch_dispatch;
        if (block.successors.size() <= 2 && !switch_dispatch) continue;
        ControlFlowRegion region;
        region.kind = ControlFlowRegionKind::Switch;
        region.header = block.id;
        region.safe_to_render = !block.instructions.empty() && block.instructions.back().is_switch_dispatch;
        if (region.safe_to_render) region.switch_expression = block.instructions.back().switch_expression;
        for (std::size_t i = 0; i < block.successors.size(); ++i) {
            region.switch_cases.emplace_back(BitVector(32, static_cast<std::uint64_t>(i)),
                                             block.successors[i]);
        }
        add_region(function.control_flow, std::move(region));
    }

    // Classify two-way branch regions. Immediate common successors are a
    // conservative join-point test; otherwise the labels are retained.
    for (const auto& block : blocks) {
        if (block.successors.size() != 2 || block.instructions.empty()) continue;
        if (has_region(function.control_flow, ControlFlowRegionKind::While, block.id) ||
            has_region(function.control_flow, ControlFlowRegionKind::Irreducible, block.id)) {
            continue;
        }
        const auto& last = block.instructions.back();
        if (last.kind != InstructionKind::ConditionalJump) continue;
        const auto true_successor = last.has_target
                                         ? std::find_if(block.successors.begin(), block.successors.end(),
                                                        [&](std::uint32_t id) {
                                                            return blocks[id].address == last.target;
                                                        })
                                         : block.successors.end();
        const auto first = true_successor == block.successors.end() ? block.successors[0] : *true_successor;
        const auto second = first == block.successors[0] ? block.successors[1] : block.successors[0];
        std::uint32_t follow = no_block;
        // The common one-block form is the dominant compiler output:
        // condition ? body : follow, with body jumping to follow.
        if (contains(blocks[first].successors, second)) follow = second;
        if (follow == no_block && contains(blocks[second].successors, first)) follow = first;
        for (const auto candidate : blocks[first].successors) {
            if (contains(blocks[second].successors, candidate)) {
                follow = candidate;
                break;
            }
        }
        ControlFlowRegion region;
        region.kind = follow == no_block ? ControlFlowRegionKind::If : ControlFlowRegionKind::IfElse;
        region.header = block.id;
        region.follow = follow;
        region.body.push_back(first);
        region.alternate.push_back(second);
        region.safe_to_render = follow != no_block &&
                                (region.kind == ControlFlowRegionKind::If ||
                                 (blocks[first].successors.size() <= 1 && blocks[second].successors.size() <= 1));
        if (follow == second) {
            region.kind = ControlFlowRegionKind::If;
            region.alternate.clear();
        }
        if (follow == first) {
            region.kind = ControlFlowRegionKind::If;
            region.invert_condition = true;
            region.body = {second};
            region.alternate.clear();
        }
        add_region(function.control_flow, std::move(region));
    }

    std::sort(function.control_flow.regions.begin(), function.control_flow.regions.end(),
              [](const ControlFlowRegion& lhs, const ControlFlowRegion& rhs) {
                  if (lhs.header != rhs.header) return lhs.header < rhs.header;
                  return static_cast<int>(lhs.kind) < static_cast<int>(rhs.kind);
              });
}

} // namespace guapseudo
