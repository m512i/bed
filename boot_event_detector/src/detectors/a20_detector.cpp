#include "detectors/a20_detector.h"
#include <intel.hpp>
#include "core/safe_decode.h"

bool A20Detector::matches(ea_t ea) {
    insn_t insn;
    if (safe_decode_insn(&insn, ea) <= 0)
        return false;

    if (insn.itype == NN_out
        && insn.ops[0].type == o_imm
        && insn.ops[0].value == 0x92)
    {
        return true;
    }

    if (insn.itype == NN_out
        && insn.ops[0].type == o_imm
        && (insn.ops[0].value == 0x64 || insn.ops[0].value == 0x60))
    {

        return detect_method(ea) == A20_KBD_CTRL;
    }

    if (insn.itype == NN_int
        && insn.ops[0].type == o_imm
        && insn.ops[0].value == 0x15)
    {
        bool found = false;
        walk_backward(ea, 20, [&](const insn_t &prev, ea_t) -> bool {
            if (prev.itype == NN_mov
                && prev.ops[0].type == o_reg
                && prev.ops[0].reg == R_ax
                && prev.ops[1].type == o_imm
                && prev.ops[1].value == 0x2401)
            {
                found = true;
                return true;
            }

            if (prev.ops[0].type == o_reg && prev.ops[0].reg == R_ax)
                return true;
            return false;
        });
        if (found) return true;
    }

    return false;
}

A20Detector::A20Method A20Detector::detect_method(ea_t ea) const {
    insn_t insn;
    if (safe_decode_insn(&insn, ea) <= 0)
        return A20_NONE;

    if (insn.itype == NN_out
        && insn.ops[0].type == o_imm
        && insn.ops[0].value == 0x92)
    {
        return A20_FAST_GATE;
    }

    if (insn.itype == NN_out
        && insn.ops[0].type == o_imm
        && insn.ops[0].value == 0x64)
    {
        A20Method result = A20_NONE;
        walk_backward(ea, 20, [&](const insn_t &prev, ea_t) -> bool {
            if (prev.itype == NN_mov
                && prev.ops[0].type == o_reg
                && prev.ops[0].reg == R_al
                && prev.ops[1].type == o_imm)
            {
                uint32 val = (uint32)prev.ops[1].value;
                if (val == 0xD1 || val == 0xDF)
                    result = A20_KBD_CTRL;
                return true;
            }
            return false;
        });
        if (result != A20_NONE) return result;
    }

    if (insn.itype == NN_out
        && insn.ops[0].type == o_imm
        && insn.ops[0].value == 0x60)
    {
        A20Method result = A20_NONE;
        walk_backward(ea, 30, [&](const insn_t &prev, ea_t) -> bool {
            if (prev.itype == NN_out
                && prev.ops[0].type == o_imm
                && prev.ops[0].value == 0x64)
            {
                result = A20_KBD_CTRL;
                return true;
            }
            return false;
        });
        if (result != A20_NONE) return result;
    }

    return A20_NONE;
}

BootEvent *A20Detector::analyze(ea_t ea) {
    insn_t insn;
    if (safe_decode_insn(&insn, ea) <= 0)
        return nullptr;

    A20Method method = detect_method(ea);
    auto *evt = new BootEvent(ea, EventType::A20_ENABLE, "");

    switch (method) {
        case A20_FAST_GATE: {
            evt->add_signal("port 0x92 write", true);

            bool rmw = false;
            walk_backward(ea, 20, [&](const insn_t &prev, ea_t) -> bool {
                if (prev.itype == NN_in
                    && prev.ops[1].type == o_imm
                    && prev.ops[1].value == 0x92)
                {
                    rmw = true;
                    return true;
                }
                return false;
            });
            evt->add_signal("read-modify-write", rmw, false);
            break;
        }
        case A20_KBD_CTRL:
            evt->add_signal("keyboard controller cmd", true);
            evt->add_signal("A20 command byte (0xD1/0xDF)", true);
            break;
        default:

            evt->add_signal("INT 15h", true);
            evt->add_signal("AX=2401h", true);
            break;
    }

    evt->compute_tier();
    return evt;
}
