#include "detectors/segment_setup_detector.h"
#include <intel.hpp>
#include "core/safe_decode.h"

bool SegmentSetupDetector::matches(ea_t ea) {
    insn_t insn;
    if (safe_decode_insn(&insn, ea) <= 0)
        return false;

    if (insn.itype == NN_mov
        && insn.ops[0].type == o_reg)
    {
        int reg = insn.ops[0].reg;

        if (reg == R_ds || reg == R_es || reg == R_ss
            || reg == R_fs || reg == R_gs)
        {
            return true;
        }
    }
    return false;
}

bool SegmentSetupDetector::is_stack_setup(ea_t ea) const {
    insn_t insn;
    if (safe_decode_insn(&insn, ea) <= 0)
        return false;

    if (insn.itype == NN_mov
        && insn.ops[0].type == o_reg
        && insn.ops[0].reg == R_ss)
    {
        return walk_forward(ea + insn.size, 15, [](const insn_t &next, ea_t) -> bool {
            return next.itype == NN_mov
                && next.ops[0].type == o_reg
                && next.ops[0].reg == R_sp;
        });
    }

    return false;
}

const char *SegmentSetupDetector::seg_reg_name(int reg) {
    switch (reg) {
        case R_ds: return "DS";
        case R_es: return "ES";
        case R_ss: return "SS";
        case R_fs: return "FS";
        case R_gs: return "GS";
        default:   return "??";
    }
}

BootEvent *SegmentSetupDetector::analyze(ea_t ea) {
    insn_t insn;
    if (safe_decode_insn(&insn, ea) <= 0)
        return nullptr;

    int reg = insn.ops[0].reg;

    if (is_stack_setup(ea)) {
        auto *evt = new BootEvent(ea, EventType::STACK_SETUP, "");
        evt->add_signal("mov SS", true);

        bool sp_found = false;
        walk_forward(ea + insn.size, 15, [&](const insn_t &next, ea_t) -> bool {
            if (next.itype == NN_mov
                && next.ops[0].type == o_reg
                && next.ops[0].reg == R_sp
                && next.ops[1].type == o_imm)
            {
                char buf[32];
                qsnprintf(buf, sizeof(buf), "SP=0x%X", (unsigned)next.ops[1].value);
                evt->details = buf;
                sp_found = true;
                return true;
            }
            return false;
        });
        evt->add_signal("mov SP follows", sp_found);

        evt->compute_tier();
        return evt;
    }

    auto *evt = new BootEvent(ea, EventType::SEGMENT_SETUP, "");

    std::string sig_name = "mov ";
    sig_name += seg_reg_name(reg);
    evt->add_signal(sig_name, true);

    bool imm_value = (insn.ops[1].type == o_imm);
    evt->add_signal("immediate value", imm_value, false);

    int seg_count = 0;
    walk_forward(ea + insn.size, 20, [&](const insn_t &next, ea_t) -> bool {
        if (next.itype == NN_mov
            && next.ops[0].type == o_reg
            && (next.ops[0].reg == R_ds || next.ops[0].reg == R_es
                || next.ops[0].reg == R_ss || next.ops[0].reg == R_fs
                || next.ops[0].reg == R_gs))
        {
            seg_count++;
        }
        return false;
    });

    bool multi = (seg_count >= 2);
    evt->add_signal("multiple seg loads nearby", multi, false);
    if (multi) {
        char buf[32];
        qsnprintf(buf, sizeof(buf), "+ %d more seg loads", seg_count);
        evt->details = buf;
    }

    evt->compute_tier();
    return evt;
}
