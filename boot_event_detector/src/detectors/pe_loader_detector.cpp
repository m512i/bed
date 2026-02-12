#include "detectors/pe_loader_detector.h"
#include <bytes.hpp>
#include <segment.hpp>
#include <intel.hpp>
#include "core/safe_decode.h"

bool PeLoaderDetector::validate_pe(ea_t mz_ea) const {

    if (!is_loaded(mz_ea) || !is_loaded(mz_ea + 1))
        return false;
    if (get_byte(mz_ea) != 'M' || get_byte(mz_ea + 1) != 'Z')
        return false;

    if (!is_loaded(mz_ea + 0x3F))
        return false;
    uint32 lfanew = get_dword(mz_ea + 0x3C);

    if (lfanew == 0 || lfanew > 0x1000)
        return false;

    ea_t pe_ea = mz_ea + lfanew;
    if (!is_loaded(pe_ea) || !is_loaded(pe_ea + 3))
        return false;

    return (get_byte(pe_ea) == 'P' && get_byte(pe_ea + 1) == 'E'
         && get_byte(pe_ea + 2) == 0 && get_byte(pe_ea + 3) == 0);
}

bool PeLoaderDetector::matches(ea_t ea) {

    if (ea & 1)
        return false;
    if (!is_loaded(ea) || !is_loaded(ea + 1))
        return false;

    if (get_byte(ea) != 'M' || get_byte(ea + 1) != 'Z')
        return false;

    return validate_pe(ea);
}

BootEvent *PeLoaderDetector::analyze(ea_t ea) {
    if (!validate_pe(ea))
        return nullptr;

    auto *evt = new BootEvent(ea, EventType::PE_LOADER, "");

    evt->add_signal("MZ header", true);

    uint32 lfanew = get_dword(ea + 0x3C);
    ea_t pe_ea = ea + lfanew;

    evt->add_signal("PE signature (PE\\0\\0)", true);

    bool has_coff = false;
    uint16 machine = 0;
    uint16 num_sections = 0;
    if (is_loaded(pe_ea + 5)) {
        machine = get_word(pe_ea + 4);
        num_sections = get_word(pe_ea + 6);
        has_coff = true;
    }
    evt->add_signal("COFF header parsed", has_coff, false);

    bool is_pe32plus = false;
    uint32 entry_rva = 0;
    if (is_loaded(pe_ea + 0x2B)) {
        uint16 opt_magic = get_word(pe_ea + 0x18);
        is_pe32plus = (opt_magic == 0x20B);

        if (is_pe32plus && is_loaded(pe_ea + 0x1F)) {
            entry_rva = get_dword(pe_ea + 0x1C);
        } else if (!is_pe32plus && is_loaded(pe_ea + 0x1F)) {
            entry_rva = get_dword(pe_ea + 0x1C);
        }
    }

    char det_buf[256];
    const char *mach_str = "unknown";
    switch (machine) {
        case 0x014C: mach_str = "i386"; break;
        case 0x8664: mach_str = "x86_64"; break;
        case 0xAA64: mach_str = "ARM64"; break;
        case 0x01C0: mach_str = "ARM"; break;
        case 0x0200: mach_str = "IA64"; break;
        case 0x0EBC: mach_str = "EFI_BC"; break;
    }

    qsnprintf(det_buf, sizeof(det_buf),
        "PE %s at 0x%llX, machine=%s (0x%04X), sections=%d, entry_rva=0x%X",
        is_pe32plus ? "PE32+" : "PE32",
        (unsigned long long)ea,
        mach_str, machine, num_sections, entry_rva);
    evt->details = det_buf;

    if (machine == 0x0EBC)
        evt->add_signal("EFI Byte Code machine", true, false);

    segment_t *seg = getseg(ea);
    if (seg) {
        ea_t seg_size = seg->end_ea - seg->start_ea;
        bool reasonable_size = (seg_size >= 512 && seg_size <= 0x10000000);
        evt->add_signal("reasonable image size", reasonable_size, false);
    }

    evt->compute_tier();
    return evt;
}
