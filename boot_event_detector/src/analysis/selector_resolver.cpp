#include "analysis/selector_resolver.h"
#include "core/safe_decode.h"
#include <intel.hpp>
#include <kernwin.hpp>

void SelectorResolver::scan_far_refs(const std::vector<BootEvent *> &events) {
    refs_.clear();

    for (auto *evt : events) {
        if (evt->suppressed)
            continue;
        if (evt->type != EventType::PMODE_ENTER
            && evt->type != EventType::LONGMODE_ENTER)
            continue;

        walk_forward(evt->address, 64, [&](const insn_t &insn, ea_t addr) -> bool {
            bool is_far_jmp = (insn.itype == NN_jmpfi
                || (insn.itype == NN_jmp && insn.ops[0].type == o_far));
            bool is_far_call = (insn.itype == NN_callfi
                || (insn.itype == NN_call && insn.ops[0].type == o_far));

            if (!is_far_jmp && !is_far_call)
                return false;

            FarReference ref;
            ref.address = addr;
            ref.is_jump = is_far_jmp;
            ref.is_call = is_far_call;
            ref.selector = 0;
            ref.target_offset = 0;
            ref.resolved_ok = false;

            if (insn.ops[0].type == o_far) {
                ref.selector = (uint16)(insn.ops[0].addr >> 32);
                ref.target_offset = insn.ops[0].addr & 0xFFFFFFFF;
                if (ref.selector == 0) {
                    ref.selector = (uint16)insn.ops[0].specval;
                }
            }

            if (ref.selector != 0 && gdt_.valid()) {
                ref.resolved = DescriptorTableResolver::resolve_selector(gdt_, ref.selector);
                ref.resolved_ok = ref.resolved.present;
            }

            refs_.push_back(ref);
            return true;
        });
    }

    if (!refs_.empty()) {
        msg("[BootEventDetector] SelectorResolver: %d far references found\n",
            (int)refs_.size());
        for (const auto &ref : refs_) {
            msg("[BootEventDetector]   0x%llX: %s sel=0x%04X -> %s\n",
                (unsigned long long)ref.address,
                ref.is_jump ? "jmp far" : "call far",
                ref.selector,
                ref.resolved_ok ? ref.resolved.summary().c_str() : "(unresolved)");
        }
    }
}

void SelectorResolver::enrich_events(std::vector<BootEvent *> &events) const {
    std::map<ea_t, const FarReference *> ref_map;
    for (const auto &ref : refs_)
        ref_map[ref.address] = &ref;

    for (auto *evt : events) {
        if (evt->suppressed)
            continue;

        for (ea_t rel : evt->related) {
            auto it = ref_map.find(rel);
            if (it != ref_map.end()) {
                const FarReference *ref = it->second;
                char buf[128];
                if (ref->resolved_ok) {
                    qsnprintf(buf, sizeof(buf), " [far %s sel=0x%04X -> %s DPL=%d]",
                        ref->is_jump ? "jmp" : "call",
                        ref->selector,
                        ref->resolved.decode_type().c_str(),
                        ref->resolved.dpl);
                } else {
                    qsnprintf(buf, sizeof(buf), " [far %s sel=0x%04X]",
                        ref->is_jump ? "jmp" : "call",
                        ref->selector);
                }
                evt->details += buf;
                break;
            }
        }
    }
}
