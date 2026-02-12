#include "detectors/longmode_detector.h"
#include <intel.hpp>
#include <bytes.hpp>
#include "core/safe_decode.h"

static const uint32 EFER_MSR = 0xC0000080;

bool LongModeDetector::matches(ea_t ea) {

    if (!is_loaded(ea) || !is_loaded(ea + 1))
        return false;
    if (get_byte(ea) == 0x0F && get_byte(ea + 1) == 0x30) {
        return is_efer_write(ea);
    }

    insn_t insn;
    if (safe_decode_insn(&insn, ea) <= 0)
        return false;
    if (insn.itype == NN_wrmsr) {
        return is_efer_write(ea);
    }
    return false;
}

bool LongModeDetector::is_efer_write(ea_t ea) const {

    bool found = false;
    walk_backward(ea, 40, [&](const insn_t &insn, ea_t) -> bool {
        if (insn.itype == NN_mov
            && insn.ops[0].type == o_reg
            && insn.ops[0].reg == R_cx
            && insn.ops[1].type == o_imm)
        {
            found = ((uint32)insn.ops[1].value == EFER_MSR);
            return true;
        }

        if (insn.ops[0].type == o_reg && insn.ops[0].reg == R_cx)
            return true;
        return false;
    });
    if (found)
        return true;

    ea_t limit = (ea > 40) ? (ea - 40) : 0;
    for (ea_t cur = ea - 1; cur >= limit && cur != BADADDR; cur--) {
        if (!is_loaded(cur))
            continue;
        uint8 b = get_byte(cur);

        if (b == 0xB9 && is_loaded(cur + 4)) {
            uint32 val = get_dword(cur + 1);
            if (val == EFER_MSR)
                return true;
        }

        if (b == 0x66 && is_loaded(cur + 5)) {
            if (get_byte(cur + 1) == 0xB9) {
                uint32 val = get_dword(cur + 2);
                if (val == EFER_MSR)
                    return true;
            }
        }
    }
    return false;
}

bool LongModeDetector::has_pae_nearby(ea_t ea, int range) const {
    return walk_backward(ea, range * 3, [](const insn_t &insn, ea_t) -> bool {
        return insn.itype == NN_movsp
            && insn.ops[0].type == o_crreg
            && insn.ops[0].reg == 4;
    });
}

bool LongModeDetector::has_cr0_pg_nearby(ea_t ea, int range) const {

    bool found = false;
    walk_backward(ea, range * 3, [&](const insn_t &insn, ea_t) -> bool {
        if (insn.itype == NN_movsp
            && insn.ops[0].type == o_crreg
            && insn.ops[0].reg == 0)
        {
            found = true;
            return true;
        }
        return false;
    });
    if (found) return true;

    walk_forward(ea + 2, range * 5, [&](const insn_t &insn, ea_t) -> bool {
        if (insn.itype == NN_movsp
            && insn.ops[0].type == o_crreg
            && insn.ops[0].reg == 0)
        {
            found = true;
            return true;
        }
        return false;
    });
    return found;
}

bool LongModeDetector::has_far_jump_ahead(ea_t ea, int lookahead) const {
    return walk_forward(ea + 2, lookahead * 5, [](const insn_t &insn, ea_t) -> bool {
        if (insn.itype == NN_jmpfi || insn.itype == NN_jmpni)
            return true;
        if (insn.itype == NN_jmp && insn.ops[0].type == o_far)
            return true;
        return false;
    });
}

BootEvent *LongModeDetector::analyze(ea_t ea) {
    auto *evt = new BootEvent(ea, EventType::LONGMODE_ENTER, "");
    evt->add_signal("EFER MSR write (0xC0000080)", true);

    bool pae = has_pae_nearby(ea);
    evt->add_signal("PAE enabled", pae);

    bool cr0_pg = has_cr0_pg_nearby(ea);
    evt->add_signal("CR0.PG set", cr0_pg);

    bool far_jmp = has_far_jump_ahead(ea);
    evt->add_signal("far jump to 64-bit", far_jmp);

    bool lme_set = false;
    walk_backward(ea, 20, [&](const insn_t &insn, ea_t) -> bool {
        if (insn.itype == NN_or
            && insn.ops[0].type == o_reg
            && insn.ops[0].reg == R_ax
            && insn.ops[1].type == o_imm
            && (insn.ops[1].value & 0x100))
        {
            lme_set = true;
            return true;
        }
        return false;
    });
    evt->add_signal("LME bit set", lme_set);

    evt->compute_tier();
    return evt;
}
