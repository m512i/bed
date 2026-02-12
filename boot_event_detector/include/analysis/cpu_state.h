#ifndef BOOT_EVENT_DETECTOR_CPU_STATE_H
#define BOOT_EVENT_DETECTOR_CPU_STATE_H

#include <ida.hpp>
#include <string>
#include <cstdint>

enum class CpuMode {
    REAL_16,
    PROTECTED_32,
    LONG_64,
    UNKNOWN
};

struct CR0Bits {
    bool PE = false;   // bit 0  — Protection Enable
    bool MP = false;   // bit 1  — Monitor Coprocessor
    bool EM = false;   // bit 2  — Emulation
    bool TS = false;   // bit 3  — Task Switched
    bool ET = false;   // bit 4  — Extension Type
    bool NE = false;   // bit 5  — Numeric Error
    bool WP = false;   // bit 16 — Write Protect
    bool AM = false;   // bit 18 — Alignment Mask
    bool NW = false;   // bit 29 — Not Write-through
    bool CD = false;   // bit 30 — Cache Disable
    bool PG = false;   // bit 31 — Paging

    void apply(uint64 val);
    void apply_or(uint64 val);
    uint64 to_bits() const;
    std::string decode() const;
};

struct CR4Bits {
    bool VME        = false;  // bit 0
    bool PVI        = false;  // bit 1
    bool TSD        = false;  // bit 2
    bool DE         = false;  // bit 3
    bool PSE        = false;  // bit 4  — Page Size Extension
    bool PAE        = false;  // bit 5  — Physical Address Extension
    bool MCE        = false;  // bit 6
    bool PGE        = false;  // bit 7  — Page Global Enable
    bool PCE        = false;  // bit 8
    bool OSFXSR     = false;  // bit 9
    bool OSXMMEXCPT = false;  // bit 10
    bool UMIP       = false;  // bit 11
    bool LA57       = false;  // bit 12 — 5-level paging
    bool VMXE       = false;  // bit 13
    bool SMXE       = false;  // bit 14
    bool FSGSBASE   = false;  // bit 16
    bool PCIDE      = false;  // bit 17
    bool OSXSAVE    = false;  // bit 18
    bool SMEP       = false;  // bit 20
    bool SMAP       = false;  // bit 21
    bool PKE        = false;  // bit 22

    void apply(uint64 val);
    void apply_or(uint64 val);
    uint64 to_bits() const;
    std::string decode() const;
};

struct EFERBits {
    bool SCE  = false;  // bit 0  — Syscall Extensions
    bool LME  = false;  // bit 8  — Long Mode Enable
    bool LMA  = false;  // bit 10 — Long Mode Active
    bool NXE  = false;  // bit 11 — No Execute Enable

    void apply(uint64 val);
    void apply_or(uint64 val);
    uint64 to_bits() const;
    std::string decode() const;
};

struct CpuState {
    CR0Bits  cr0;
    uint64   cr3 = 0;
    CR4Bits  cr4;
    EFERBits efer;

    CpuMode mode = CpuMode::REAL_16;
    ea_t    last_transition_ea = BADADDR;

    CpuMode derive_mode() const;

    void update_mode(ea_t ea);

    std::string summary() const;

    static const char *mode_to_string(CpuMode m);
};

struct StateSnapshot {
    ea_t     address;
    CpuState state;
    CpuMode  prev_mode;
    CpuMode  new_mode;
    std::string trigger;
};

#endif
