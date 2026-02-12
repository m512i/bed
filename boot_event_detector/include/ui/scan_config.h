#ifndef BOOT_EVENT_DETECTOR_SCAN_CONFIG_H
#define BOOT_EVENT_DETECTOR_SCAN_CONFIG_H

#include <ida.hpp>
#include <kernwin.hpp>

struct ScanConfig {

    bool detect_gdt_idt;
    bool detect_pmode;
    bool detect_paging;
    bool detect_longmode;
    bool detect_a20;
    bool detect_bios_disk;
    bool detect_video_mode;
    bool detect_memmap;
    bool detect_segment_setup;

    bool detect_stage;
    bool detect_uefi_boot_svc;
    bool detect_uefi_protocol;
    bool detect_multiboot;
    bool detect_pe_loader;

    ea_t range_start;
    ea_t range_end;

    bool suppress_kernel_segments;

    ScanConfig()
        : detect_gdt_idt(true)
        , detect_pmode(true)
        , detect_paging(true)
        , detect_longmode(true)
        , detect_a20(true)
        , detect_bios_disk(true)
        , detect_video_mode(true)
        , detect_memmap(true)
        , detect_segment_setup(true)
        , detect_stage(true)
        , detect_uefi_boot_svc(true)
        , detect_uefi_protocol(true)
        , detect_multiboot(true)
        , detect_pe_loader(true)
        , range_start(0)
        , range_end(0)
        , suppress_kernel_segments(true)
    {}

    static bool show_dialog(ScanConfig &cfg);
};

#endif
