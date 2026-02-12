#include "detectors/multiboot_detector.h"
#include <bytes.hpp>
#include <segment.hpp>
#include "core/safe_decode.h"

bool MultibootDetector::matches(ea_t ea) {

    if (ea & 3)
        return false;
    if (!is_loaded(ea) || !is_loaded(ea + 3))
        return false;

    uint32 val = get_dword(ea);
    if (val == MB1_MAGIC)
        return true;

    if (val == MB2_MAGIC && (ea & 7) == 0)
        return true;

    return false;
}

BootEvent *MultibootDetector::analyze(ea_t ea) {
    if (!is_loaded(ea) || !is_loaded(ea + 3))
        return nullptr;

    uint32 magic = get_dword(ea);
    auto *evt = new BootEvent(ea, EventType::MULTIBOOT_HEADER, "");

    if (magic == MB1_MAGIC) {
        evt->add_signal("Multiboot1 magic (0x1BADB002)", true);

        if (is_loaded(ea + 11)) {
            uint32 flags = get_dword(ea + 4);
            uint32 checksum = get_dword(ea + 8);
            bool valid = ((magic + flags + checksum) == 0);
            evt->add_signal("checksum valid", valid);

            char flag_buf[64];
            qsnprintf(flag_buf, sizeof(flag_buf), "flags=0x%08X", flags);
            evt->details = "Multiboot1 header, ";
            evt->details += flag_buf;

            if (flags & (1 << 0))
                evt->details += " [ALIGN_MODULES]";
            if (flags & (1 << 1))
                evt->details += " [MEMINFO]";
            if (flags & (1 << 2))
                evt->details += " [VIDEO]";
            if (flags & (1 << 16))
                evt->details += " [AOUT_KLUDGE]";
        } else {
            evt->add_signal("checksum valid", false);
            evt->details = "Multiboot1 header (truncated)";
        }
    } else if (magic == MB2_MAGIC) {
        evt->add_signal("Multiboot2 magic (0xE85250D6)", true);

        if (is_loaded(ea + 15)) {
            uint32 arch = get_dword(ea + 4);
            uint32 length = get_dword(ea + 8);
            uint32 checksum = get_dword(ea + 12);
            bool valid = ((magic + arch + length + checksum) == 0);
            evt->add_signal("checksum valid", valid);

            char det_buf[128];
            qsnprintf(det_buf, sizeof(det_buf),
                "Multiboot2 header, arch=%s, length=%d",
                (arch == 0) ? "i386" : (arch == 4) ? "MIPS" : "unknown",
                length);
            evt->details = det_buf;
        } else {
            evt->add_signal("checksum valid", false);
            evt->details = "Multiboot2 header (truncated)";
        }
    } else {
        delete evt;
        return nullptr;
    }

    evt->compute_tier();
    return evt;
}
