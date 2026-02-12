#include "detectors/video_mode_detector.h"
#include <intel.hpp>
#include "core/safe_decode.h"

bool VideoModeDetector::matches(ea_t ea) {
    insn_t insn;
    if (safe_decode_insn(&insn, ea) <= 0)
        return false;

    if (insn.itype == NN_int
        && insn.ops[0].type == o_imm
        && insn.ops[0].value == 0x10)
    {
        int ah = get_ah_value(ea);

        return (ah == 0x00 || ah == 0x4F);
    }
    return false;
}

int VideoModeDetector::get_ah_value(ea_t ea) const {
    int result = -1;
    walk_backward(ea, 30, [&](const insn_t &insn, ea_t) -> bool {
        if (insn.itype == NN_mov && insn.ops[0].type == o_reg) {
            if (insn.ops[0].reg == R_ah && insn.ops[1].type == o_imm) {
                result = (int)insn.ops[1].value;
                return true;
            }
            if (insn.ops[0].reg == R_ax && insn.ops[1].type == o_imm) {
                result = (int)((insn.ops[1].value >> 8) & 0xFF);
                return true;
            }

            if (insn.ops[0].reg == R_ax || insn.ops[0].reg == R_ah)
                return true;
        }
        return false;
    });
    return result;
}

int VideoModeDetector::get_ax_value(ea_t ea) const {
    int result = -1;
    walk_backward(ea, 30, [&](const insn_t &insn, ea_t) -> bool {
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

int VideoModeDetector::get_al_value(ea_t ea) const {
    int result = -1;
    walk_backward(ea, 30, [&](const insn_t &insn, ea_t) -> bool {
        if (insn.itype == NN_mov && insn.ops[0].type == o_reg) {
            if (insn.ops[0].reg == R_al && insn.ops[1].type == o_imm) {
                result = (int)insn.ops[1].value;
                return true;
            }
            if (insn.ops[0].reg == R_ax && insn.ops[1].type == o_imm) {
                result = (int)(insn.ops[1].value & 0xFF);
                return true;
            }
            if (insn.ops[0].reg == R_ax || insn.ops[0].reg == R_al)
                return true;
        }
        return false;
    });
    return result;
}

BootEvent *VideoModeDetector::analyze(ea_t ea) {
    insn_t insn;
    if (safe_decode_insn(&insn, ea) <= 0)
        return nullptr;

    int ah = get_ah_value(ea);
    auto *evt = new BootEvent(ea, EventType::VIDEO_MODE_SWITCH, "");
    evt->add_signal("INT 10h", true);

    if (ah == 0x00) {
        evt->add_signal("AH=00h (set mode)", true);
        int al = get_al_value(ea);
        bool mode_resolved = (al >= 0);
        evt->add_signal("mode number resolved", mode_resolved, false);
        if (mode_resolved) {
            char buf[32];
            qsnprintf(buf, sizeof(buf), "mode=0x%02X", al);
            evt->details = buf;
        }
    } else if (ah == 0x4F) {
        int ax = get_ax_value(ea);
        if (ax == 0x4F02) {
            evt->add_signal("AX=4F02h (VESA set mode)", true);
        } else if (ax == 0x4F01) {
            evt->add_signal("AX=4F01h (VESA get mode info)", true);
        } else if (ax == 0x4F00) {
            evt->add_signal("AX=4F00h (VESA get VBE info)", true);
        } else {
            evt->add_signal("AH=4Fh (VESA)", true);
        }
    } else {
        evt->add_signal("AH resolved", false);
    }

    evt->compute_tier();
    return evt;
}
