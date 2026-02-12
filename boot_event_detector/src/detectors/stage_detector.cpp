#include "detectors/stage_detector.h"
#include <segment.hpp>
#include <bytes.hpp>
#include <intel.hpp>
#include "core/safe_decode.h"

bool StageDetector::is_mbr_signature(ea_t seg_start, ea_t seg_end) const {

    ea_t sig_ea = seg_start + 510;
    if (sig_ea + 2 > seg_end)
        return false;
    if (!is_loaded(sig_ea) || !is_loaded(sig_ea + 1))
        return false;
    return get_word(sig_ea) == 0xAA55;
}

bool StageDetector::is_vbr_signature(ea_t seg_start, ea_t seg_end) const {

    if (seg_end - seg_start < 512)
        return false;
    ea_t sig_ea = seg_start + 510;
    if (!is_loaded(sig_ea) || !is_loaded(sig_ea + 1))
        return false;
    if (get_word(sig_ea) != 0xAA55)
        return false;

    if (!is_loaded(seg_start))
        return false;
    uint8 b0 = get_byte(seg_start);
    if (b0 != 0xEB && b0 != 0xE9)
        return false;

    if (is_loaded(seg_start + 6)) {
        char sig[9] = {0};
        for (int i = 0; i < 8; i++) {
            if (is_loaded(seg_start + 3 + i))
                sig[i] = (char)get_byte(seg_start + 3 + i);
        }
        if (strstr(sig, "NTFS") || strstr(sig, "FAT") || strstr(sig, "MSWIN")
            || strstr(sig, "mkdos") || strstr(sig, "MSDOS"))
            return true;
    }
    return false;
}

bool StageDetector::is_uefi_entry(ea_t ea) const {

    bool found_table_access = false;
    walk_forward(ea, 64, [&](const insn_t &insn, ea_t) -> bool {

        if (insn.itype == NN_mov && insn.ops[1].type == o_displ) {
            if (insn.ops[1].reg == R_dx) {
                if (insn.ops[1].addr == 0x60 || insn.ops[1].addr == 0x58) {
                    found_table_access = true;
                    return true;
                }
            }
        }
        return false;
    });
    return found_table_access;
}

bool StageDetector::matches(ea_t ea) {
    segment_t *seg = getseg(ea);
    if (!seg)
        return false;

    if (ea != seg->start_ea)
        return false;

    if (is_mbr_signature(seg->start_ea, seg->end_ea))
        return true;

    if (seg->is_64bit() && is_uefi_entry(ea))
        return true;

    return false;
}

BootEvent *StageDetector::analyze(ea_t ea) {
    segment_t *seg = getseg(ea);
    if (!seg)
        return nullptr;

    auto *evt = new BootEvent(ea, EventType::STAGE_DETECT, "");

    bool is_mbr = false;
    bool is_vbr = false;

    if (is_mbr_signature(seg->start_ea, seg->end_ea)) {
        is_vbr = is_vbr_signature(seg->start_ea, seg->end_ea);
        is_mbr = !is_vbr;
    }

    if (is_mbr) {
        evt->add_signal("0xAA55 boot signature", true);
        evt->add_signal("BPB filesystem header", false, false);

        bool at_7c00 = (seg->start_ea == 0x7C00);
        evt->add_signal("loaded at 0x7C00", at_7c00, false);

        ea_t seg_size = seg->end_ea - seg->start_ea;
        bool is_512 = (seg_size >= 510 && seg_size <= 1024);
        evt->add_signal("segment ~512 bytes", is_512, false);

        evt->details = "MBR boot sector";
        if (at_7c00)
            evt->details += " at 0x7C00";
    } else if (is_vbr) {
        evt->add_signal("0xAA55 boot signature", true);
        evt->add_signal("BPB filesystem header", true);
        evt->add_signal("short jmp at offset 0", true, false);
        evt->details = "VBR (Volume Boot Record)";
    } else if (seg->is_64bit() && is_uefi_entry(ea)) {
        evt->add_signal("64-bit segment", true);
        evt->add_signal("SystemTable access (RDX+0x60)", true);
        evt->add_signal("UEFI entry signature", true, false);
        evt->details = "UEFI DXE/Application entry";
    } else {
        delete evt;
        return nullptr;
    }

    evt->compute_tier();
    return evt;
}
