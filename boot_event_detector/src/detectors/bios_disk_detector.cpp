#include "detectors/bios_disk_detector.h"
#include <intel.hpp>
#include "core/safe_decode.h"

bool BiosDiskDetector::matches(ea_t ea) {
    insn_t insn;
    if (safe_decode_insn(&insn, ea) <= 0)
        return false;

    if (insn.itype == NN_int
        && insn.ops[0].type == o_imm
        && insn.ops[0].value == 0x13)
    {
        int ah = get_ah_value(ea);

        return (ah == 0x02 || ah == 0x42);
    }
    return false;
}

int BiosDiskDetector::get_ah_value(ea_t ea) const {
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

int BiosDiskDetector::get_dl_value(ea_t ea) const {
    int result = -1;
    walk_backward(ea, 30, [&](const insn_t &insn, ea_t) -> bool {
        if (insn.itype == NN_mov && insn.ops[0].type == o_reg) {
            if (insn.ops[0].reg == R_dl && insn.ops[1].type == o_imm) {
                result = (int)insn.ops[1].value;
                return true;
            }
            if (insn.ops[0].reg == R_dx && insn.ops[1].type == o_imm) {
                result = (int)(insn.ops[1].value & 0xFF);
                return true;
            }
            if (insn.ops[0].reg == R_dx || insn.ops[0].reg == R_dl)
                return true;
        }
        return false;
    });
    return result;
}

std::string BiosDiskDetector::parse_dap_info(ea_t ea) const {
    std::string info;
    walk_backward(ea, 30, [&](const insn_t &insn, ea_t) -> bool {

        if (insn.itype == NN_mov
            && insn.ops[0].type == o_reg
            && insn.ops[0].reg == R_si
            && insn.ops[1].type == o_imm)
        {
            ea_t dap_ea = insn.ops[1].value;
            if (is_loaded(dap_ea) && is_loaded(dap_ea + 15)) {
                uint16 sectors = get_word(dap_ea + 2);
                uint16 buf_off = get_word(dap_ea + 4);
                uint16 buf_seg = get_word(dap_ea + 6);
                uint64 lba = get_qword(dap_ea + 8);

                char buf[128];
                qsnprintf(buf, sizeof(buf),
                    ", DAP at 0x%X: %d sectors, buf=%04X:%04X, LBA=%llu",
                    (unsigned)dap_ea, sectors, buf_seg, buf_off,
                    (unsigned long long)lba);
                info = buf;
            }
            return true;
        }
        return false;
    });
    return info;
}

BootEvent *BiosDiskDetector::analyze(ea_t ea) {
    insn_t insn;
    if (safe_decode_insn(&insn, ea) <= 0)
        return nullptr;

    int ah = get_ah_value(ea);
    int dl = get_dl_value(ea);

    auto *evt = new BootEvent(ea, EventType::BIOS_DISK_READ, "");
    evt->add_signal("INT 13h", true);

    if (ah == 0x02) {
        evt->add_signal("AH=02h (CHS read)", true);
    } else if (ah == 0x42) {
        evt->add_signal("AH=42h (LBA extended)", true);
        std::string dap = parse_dap_info(ea);
        evt->add_signal("DAP parsed", !dap.empty(), false);
        if (!dap.empty())
            evt->details = dap;
    } else {
        evt->add_signal("AH resolved", false);
    }

    evt->add_signal("drive number resolved", dl >= 0, false);
    if (dl >= 0) {
        char buf[32];
        qsnprintf(buf, sizeof(buf), "drive=0x%02X", dl);
        evt->details += evt->details.empty() ? buf : std::string(", ") + buf;
    }

    evt->compute_tier();
    return evt;
}
