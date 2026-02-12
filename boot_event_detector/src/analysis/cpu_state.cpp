#include "analysis/cpu_state.h"

void CR0Bits::apply(uint64 val) {
    PE = (val >> 0)  & 1;
    MP = (val >> 1)  & 1;
    EM = (val >> 2)  & 1;
    TS = (val >> 3)  & 1;
    ET = (val >> 4)  & 1;
    NE = (val >> 5)  & 1;
    WP = (val >> 16) & 1;
    AM = (val >> 18) & 1;
    NW = (val >> 29) & 1;
    CD = (val >> 30) & 1;
    PG = (val >> 31) & 1;
}

void CR0Bits::apply_or(uint64 val) {
    if (val & (1ULL << 0))  PE = true;
    if (val & (1ULL << 1))  MP = true;
    if (val & (1ULL << 2))  EM = true;
    if (val & (1ULL << 3))  TS = true;
    if (val & (1ULL << 4))  ET = true;
    if (val & (1ULL << 5))  NE = true;
    if (val & (1ULL << 16)) WP = true;
    if (val & (1ULL << 18)) AM = true;
    if (val & (1ULL << 29)) NW = true;
    if (val & (1ULL << 30)) CD = true;
    if (val & (1ULL << 31)) PG = true;
}

uint64 CR0Bits::to_bits() const {
    uint64 v = 0;
    if (PE) v |= (1ULL << 0);
    if (MP) v |= (1ULL << 1);
    if (EM) v |= (1ULL << 2);
    if (TS) v |= (1ULL << 3);
    if (ET) v |= (1ULL << 4);
    if (NE) v |= (1ULL << 5);
    if (WP) v |= (1ULL << 16);
    if (AM) v |= (1ULL << 18);
    if (NW) v |= (1ULL << 29);
    if (CD) v |= (1ULL << 30);
    if (PG) v |= (1ULL << 31);
    return v;
}

std::string CR0Bits::decode() const {
    std::string s;
    if (PE) s += " PE";
    if (MP) s += " MP";
    if (EM) s += " EM";
    if (TS) s += " TS";
    if (ET) s += " ET";
    if (NE) s += " NE";
    if (WP) s += " WP";
    if (AM) s += " AM";
    if (NW) s += " NW";
    if (CD) s += " CD";
    if (PG) s += " PG";
    return s.empty() ? "(none)" : s.substr(1);
}

void CR4Bits::apply(uint64 val) {
    VME        = (val >> 0)  & 1;
    PVI        = (val >> 1)  & 1;
    TSD        = (val >> 2)  & 1;
    DE         = (val >> 3)  & 1;
    PSE        = (val >> 4)  & 1;
    PAE        = (val >> 5)  & 1;
    MCE        = (val >> 6)  & 1;
    PGE        = (val >> 7)  & 1;
    PCE        = (val >> 8)  & 1;
    OSFXSR     = (val >> 9)  & 1;
    OSXMMEXCPT = (val >> 10) & 1;
    UMIP       = (val >> 11) & 1;
    LA57       = (val >> 12) & 1;
    VMXE       = (val >> 13) & 1;
    SMXE       = (val >> 14) & 1;
    FSGSBASE   = (val >> 16) & 1;
    PCIDE      = (val >> 17) & 1;
    OSXSAVE    = (val >> 18) & 1;
    SMEP       = (val >> 20) & 1;
    SMAP       = (val >> 21) & 1;
    PKE        = (val >> 22) & 1;
}

void CR4Bits::apply_or(uint64 val) {
    if (val & (1ULL << 0))  VME = true;
    if (val & (1ULL << 1))  PVI = true;
    if (val & (1ULL << 2))  TSD = true;
    if (val & (1ULL << 3))  DE = true;
    if (val & (1ULL << 4))  PSE = true;
    if (val & (1ULL << 5))  PAE = true;
    if (val & (1ULL << 6))  MCE = true;
    if (val & (1ULL << 7))  PGE = true;
    if (val & (1ULL << 8))  PCE = true;
    if (val & (1ULL << 9))  OSFXSR = true;
    if (val & (1ULL << 10)) OSXMMEXCPT = true;
    if (val & (1ULL << 11)) UMIP = true;
    if (val & (1ULL << 12)) LA57 = true;
    if (val & (1ULL << 13)) VMXE = true;
    if (val & (1ULL << 14)) SMXE = true;
    if (val & (1ULL << 16)) FSGSBASE = true;
    if (val & (1ULL << 17)) PCIDE = true;
    if (val & (1ULL << 18)) OSXSAVE = true;
    if (val & (1ULL << 20)) SMEP = true;
    if (val & (1ULL << 21)) SMAP = true;
    if (val & (1ULL << 22)) PKE = true;
}

uint64 CR4Bits::to_bits() const {
    uint64 v = 0;
    if (VME)        v |= (1ULL << 0);
    if (PVI)        v |= (1ULL << 1);
    if (TSD)        v |= (1ULL << 2);
    if (DE)         v |= (1ULL << 3);
    if (PSE)        v |= (1ULL << 4);
    if (PAE)        v |= (1ULL << 5);
    if (MCE)        v |= (1ULL << 6);
    if (PGE)        v |= (1ULL << 7);
    if (PCE)        v |= (1ULL << 8);
    if (OSFXSR)     v |= (1ULL << 9);
    if (OSXMMEXCPT) v |= (1ULL << 10);
    if (UMIP)       v |= (1ULL << 11);
    if (LA57)       v |= (1ULL << 12);
    if (VMXE)       v |= (1ULL << 13);
    if (SMXE)       v |= (1ULL << 14);
    if (FSGSBASE)   v |= (1ULL << 16);
    if (PCIDE)      v |= (1ULL << 17);
    if (OSXSAVE)    v |= (1ULL << 18);
    if (SMEP)       v |= (1ULL << 20);
    if (SMAP)       v |= (1ULL << 21);
    if (PKE)        v |= (1ULL << 22);
    return v;
}

std::string CR4Bits::decode() const {
    std::string s;
    if (VME)        s += " VME";
    if (PVI)        s += " PVI";
    if (TSD)        s += " TSD";
    if (DE)         s += " DE";
    if (PSE)        s += " PSE";
    if (PAE)        s += " PAE";
    if (MCE)        s += " MCE";
    if (PGE)        s += " PGE";
    if (PCE)        s += " PCE";
    if (OSFXSR)     s += " OSFXSR";
    if (OSXMMEXCPT) s += " OSXMMEXCPT";
    if (UMIP)       s += " UMIP";
    if (LA57)       s += " LA57";
    if (VMXE)       s += " VMXE";
    if (SMXE)       s += " SMXE";
    if (FSGSBASE)   s += " FSGSBASE";
    if (PCIDE)      s += " PCIDE";
    if (OSXSAVE)    s += " OSXSAVE";
    if (SMEP)       s += " SMEP";
    if (SMAP)       s += " SMAP";
    if (PKE)        s += " PKE";
    return s.empty() ? "(none)" : s.substr(1);
}

void EFERBits::apply(uint64 val) {
    SCE = (val >> 0)  & 1;
    LME = (val >> 8)  & 1;
    LMA = (val >> 10) & 1;
    NXE = (val >> 11) & 1;
}

void EFERBits::apply_or(uint64 val) {
    if (val & (1ULL << 0))  SCE = true;
    if (val & (1ULL << 8))  LME = true;
    if (val & (1ULL << 10)) LMA = true;
    if (val & (1ULL << 11)) NXE = true;
}

uint64 EFERBits::to_bits() const {
    uint64 v = 0;
    if (SCE) v |= (1ULL << 0);
    if (LME) v |= (1ULL << 8);
    if (LMA) v |= (1ULL << 10);
    if (NXE) v |= (1ULL << 11);
    return v;
}

std::string EFERBits::decode() const {
    std::string s;
    if (SCE) s += " SCE";
    if (LME) s += " LME";
    if (LMA) s += " LMA";
    if (NXE) s += " NXE";
    return s.empty() ? "(none)" : s.substr(1);
}

CpuMode CpuState::derive_mode() const {
    if (cr0.PE && cr0.PG && efer.LME)
        return CpuMode::LONG_64;
    if (cr0.PE)
        return CpuMode::PROTECTED_32;
    return CpuMode::REAL_16;
}

void CpuState::update_mode(ea_t ea) {
    CpuMode new_mode = derive_mode();
    if (new_mode != mode) {
        last_transition_ea = ea;
        mode = new_mode;
    }
}

const char *CpuState::mode_to_string(CpuMode m) {
    switch (m) {
        case CpuMode::REAL_16:       return "REAL_16";
        case CpuMode::PROTECTED_32:  return "PROTECTED_32";
        case CpuMode::LONG_64:       return "LONG_64";
        default:                     return "UNKNOWN";
    }
}

std::string CpuState::summary() const {
    char buf[256];
    qsnprintf(buf, sizeof(buf),
        "mode=%s CR0=[%s] CR3=0x%llX CR4=[%s] EFER=[%s]",
        mode_to_string(mode),
        cr0.decode().c_str(),
        (unsigned long long)cr3,
        cr4.decode().c_str(),
        efer.decode().c_str());
    return buf;
}
