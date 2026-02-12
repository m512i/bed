#include "detectors/pmode_detector.h"
#include <intel.hpp>
#include "core/safe_decode.h"

bool PmodeDetector::matches(ea_t ea) {
    insn_t insn;
    if (safe_decode_insn(&insn, ea) <= 0)
        return false;

    if (insn.itype == NN_movsp
        && insn.ops[0].type == o_crreg
        && insn.ops[0].reg == 0)
    {
        return true;
    }
    return false;
}

bool PmodeDetector::has_far_jump_ahead(ea_t ea, int lookahead) const {
    return walk_forward(ea + 3, lookahead * 5, [](const insn_t &insn, ea_t) -> bool {
        if (insn.itype == NN_jmpfi || insn.itype == NN_jmpni)
            return true;
        if (insn.itype == NN_jmp && insn.ops[0].type == o_far)
            return true;
        return false;
    });
}

BootEvent *PmodeDetector::analyze(ea_t ea) {
    insn_t insn;
    if (safe_decode_insn(&insn, ea) <= 0)
        return nullptr;

    auto *evt = new BootEvent(ea, EventType::PMODE_ENTER, "");
    evt->add_signal("CR0 write", true);

    bool far_jmp = has_far_jump_ahead(ea);
    evt->add_signal("far jump", far_jmp);

    bool pe_set = false;
    walk_backward(ea, 20, [&](const insn_t &prev, ea_t) -> bool {
        if (prev.itype == NN_or
            && prev.ops[0].type == o_reg
            && prev.ops[1].type == o_imm
            && (prev.ops[1].value & 1))
        {
            pe_set = true;
            return true;
        }
        return false;
    });
    evt->add_signal("PE bit set", pe_set);

    evt->compute_tier();
    return evt;
}
