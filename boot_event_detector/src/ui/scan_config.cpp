#include "ui/scan_config.h"

bool ScanConfig::show_dialog(ScanConfig &cfg) {
    int choice = ask_buttons(
        "Configure",
        "Skip",
        "Cancel",
        ASKBTN_YES,
        "Boot Event Detector\n\n"
        "Configure scan settings before running?\n"
        "Press 'Skip' to scan with all defaults.");

    if (choice == ASKBTN_CANCEL)
        return false;

    if (choice == ASKBTN_NO)
        return true;

    static const char form[] =
        "Boot Event Detector - Configuration\n\n"
        "<##Detectors (v0.1-v0.2)##GDT/IDT Load:C>\n"
        "<Protected Mode Enter:C>\n"
        "<Paging Enable:C>\n"
        "<Long Mode Enter:C>\n"
        "<A20 Gate Enable:C>\n"
        "<BIOS Disk Read:C>\n"
        "<Video Mode Switch:C>\n"
        "<Memory Map Query:C>\n"
        "<Segment Register Setup:C>>\n"
        "\n"
        "<##Detectors (v0.4)##Stage Detection (MBR/VBR/UEFI):c>\n"
        "<UEFI Boot Services:c>\n"
        "<UEFI Protocol GUIDs:c>\n"
        "<Multiboot Headers:c>\n"
        "<PE/COFF Image Detection:c>>\n"
        "\n"
        "<##Options##Suppress non-boot segments in 64-bit:C>>\n"
        "\n"
        "<##Scan Range (0 = all segments)##Start address:$::18::>\n"
        "<End address  :$::18::>\n"
        "\n";

    ushort detectors = 0;
    if (cfg.detect_gdt_idt)        detectors |= (1 << 0);
    if (cfg.detect_pmode)          detectors |= (1 << 1);
    if (cfg.detect_paging)         detectors |= (1 << 2);
    if (cfg.detect_longmode)       detectors |= (1 << 3);
    if (cfg.detect_a20)            detectors |= (1 << 4);
    if (cfg.detect_bios_disk)      detectors |= (1 << 5);
    if (cfg.detect_video_mode)     detectors |= (1 << 6);
    if (cfg.detect_memmap)         detectors |= (1 << 7);
    if (cfg.detect_segment_setup)  detectors |= (1 << 8);

    ushort detectors_v04 = 0;
    if (cfg.detect_stage)          detectors_v04 |= (1 << 0);
    if (cfg.detect_uefi_boot_svc)  detectors_v04 |= (1 << 1);
    if (cfg.detect_uefi_protocol)  detectors_v04 |= (1 << 2);
    if (cfg.detect_multiboot)      detectors_v04 |= (1 << 3);
    if (cfg.detect_pe_loader)      detectors_v04 |= (1 << 4);

    ushort options = 0;
    if (cfg.suppress_kernel_segments) options |= (1 << 0);

    ea_t start = cfg.range_start;
    ea_t end = cfg.range_end;

    int ok = ask_form(form, &detectors, &detectors_v04, &options, &start, &end);
    if (!ok)
        return false;

    cfg.detect_gdt_idt       = (detectors & (1 << 0)) != 0;
    cfg.detect_pmode         = (detectors & (1 << 1)) != 0;
    cfg.detect_paging        = (detectors & (1 << 2)) != 0;
    cfg.detect_longmode      = (detectors & (1 << 3)) != 0;
    cfg.detect_a20           = (detectors & (1 << 4)) != 0;
    cfg.detect_bios_disk     = (detectors & (1 << 5)) != 0;
    cfg.detect_video_mode    = (detectors & (1 << 6)) != 0;
    cfg.detect_memmap        = (detectors & (1 << 7)) != 0;
    cfg.detect_segment_setup = (detectors & (1 << 8)) != 0;

    cfg.detect_stage         = (detectors_v04 & (1 << 0)) != 0;
    cfg.detect_uefi_boot_svc = (detectors_v04 & (1 << 1)) != 0;
    cfg.detect_uefi_protocol = (detectors_v04 & (1 << 2)) != 0;
    cfg.detect_multiboot     = (detectors_v04 & (1 << 3)) != 0;
    cfg.detect_pe_loader     = (detectors_v04 & (1 << 4)) != 0;

    cfg.suppress_kernel_segments = (options & (1 << 0)) != 0;

    cfg.range_start = start;
    cfg.range_end = end;

    return true;
}
