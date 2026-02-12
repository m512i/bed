#include "detectors/memmap_detector.h"
#include <intel.hpp>
#include "core/safe_decode.h"

bool MemMapDetector::matches(ea_t ea) {
    insn_t insn;
    if (safe_decode_insn(&insn, ea) <= 0)
        return false;

    if (insn.itype == NN_int
        && insn.ops[0].type == o_imm
        && insn.ops[0].value == 0x15)
    {
        int ax = get_ax_value(ea);

        return (ax == 0xE820);
    }
    return false;
}

int MemMapDetector::get_ax_value(ea_t ea) const {
    int result = -1;
    walk_backward(ea, 40, [&](const insn_t &insn, ea_t) -> bool {
        if (insn.itype == NN_mov && insn.ops[0].type == o_reg) {
            if (insn.ops[0].reg == R_ax && insn.ops[1].type == o_imm) {
                result = (int)(insn.ops[1].value & 0xFFFF);
                return true;
            }
            if (insn.ops[0].reg == R_ax)
                return true;
        }
        return false;
    });
    return result;
}

bool MemMapDetector::has_smap_signature(ea_t ea) const {
    return walk_backward(ea, 40, [](const insn_t &insn, ea_t) -> bool {
        return insn.itype == NN_mov
            && insn.ops[0].type == o_reg
            && insn.ops[0].reg == R_dx
            && insn.ops[1].type == o_imm
            && (uint32)insn.ops[1].value == 0x534D4150;
    });
}

BootEvent *MemMapDetector::analyze(ea_t ea) {
    insn_t insn;
    if (safe_decode_insn(&insn, ea) <= 0)
        return nullptr;

    auto *evt = new BootEvent(ea, EventType::MEMORY_MAP_QUERY, "");
    evt->add_signal("INT 15h", true);
    evt->add_signal("AX=E820h", true);

    bool smap = has_smap_signature(ea);
    evt->add_signal("EDX='SMAP' signature", smap, false);

    evt->compute_tier();
    return evt;
}
