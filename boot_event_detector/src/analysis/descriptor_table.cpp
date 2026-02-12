#include "analysis/descriptor_table.h"
#include <bytes.hpp>
#include <kernwin.hpp>

std::string SegmentDescriptor::decode_type() const {
    if (is_system) {
        switch (type & 0xF) {
            case 0x1: return "TSS16-avail";
            case 0x2: return "LDT";
            case 0x3: return "TSS16-busy";
            case 0x4: return "CallGate16";
            case 0x5: return "TaskGate";
            case 0x6: return "IntGate16";
            case 0x7: return "TrapGate16";
            case 0x9: return "TSS64-avail";
            case 0xB: return "TSS64-busy";
            case 0xC: return "CallGate64";
            case 0xE: return "IntGate64";
            case 0xF: return "TrapGate64";
            default:  return "sys-reserved";
        }
    }
    if (is_code) {
        std::string s = "Code";
        if (type & 0x2) s += "/R";
        if (type & 0x4) s += "/Conf";
        return s;
    }
    if (is_data) {
        std::string s = "Data";
        if (type & 0x2) s += "/W";
        if (type & 0x4) s += "/ExpDn";
        return s;
    }
    return "unknown";
}

std::string SegmentDescriptor::summary() const {
    char buf[256];
    uint64 effective_limit = granularity ? ((uint64)limit << 12) | 0xFFF : limit;
    qsnprintf(buf, sizeof(buf),
        "sel=0x%04X base=0x%08X limit=0x%llX DPL=%d %s%s%s %s",
        selector, base, (unsigned long long)effective_limit, dpl,
        present ? "P" : "NP",
        is_64bit ? " L" : "",
        default_32 ? " D/B" : "",
        decode_type().c_str());
    return buf;
}

SegmentDescriptor DescriptorTableResolver::parse_descriptor(ea_t entry_ea) {
    SegmentDescriptor desc = {};
    desc.selector = 0;

    if (!is_loaded(entry_ea) || !is_loaded(entry_ea + 7))
        return desc;

    uint64 raw = 0;
    for (int i = 0; i < 8; i++)
        raw |= ((uint64)get_byte(entry_ea + i)) << (i * 8);

    desc.limit = (raw & 0xFFFF) | (((raw >> 48) & 0xF) << 16);
    desc.base = ((raw >> 16) & 0xFFFF)
              | (((raw >> 32) & 0xFF) << 16)
              | (((raw >> 56) & 0xFF) << 24);

    uint8 access = (raw >> 40) & 0xFF;
    uint8 flags  = (raw >> 52) & 0xF;

    desc.present     = (access >> 7) & 1;
    desc.dpl         = (access >> 5) & 3;
    desc.is_system   = !((access >> 4) & 1);
    desc.type        = access & 0xF;
    desc.is_code     = !desc.is_system && ((access >> 3) & 1);
    desc.is_data     = !desc.is_system && !desc.is_code;
    desc.granularity = (flags >> 3) & 1;
    desc.default_32  = (flags >> 2) & 1;
    desc.is_64bit    = (flags >> 1) & 1;

    return desc;
}

DescriptorTableInfo DescriptorTableResolver::parse_gdt(ea_t desc_ptr_ea) {
    DescriptorTableInfo info = {};
    info.base_ea = BADADDR;
    info.limit = 0;
    info.entry_count = 0;

    if (!is_loaded(desc_ptr_ea) || !is_loaded(desc_ptr_ea + 5))
        return info;

    info.limit = get_word(desc_ptr_ea);
    info.base_ea = get_dword(desc_ptr_ea + 2);
    info.entry_count = (info.limit + 1) / 8;

    if (info.base_ea == 0 || !is_loaded(info.base_ea))
        return info;

    for (int i = 0; i < info.entry_count && i < 64; i++) {
        ea_t entry_ea = info.base_ea + (i * 8);
        if (!is_loaded(entry_ea) || !is_loaded(entry_ea + 7))
            break;

        SegmentDescriptor desc = parse_descriptor(entry_ea);
        desc.selector = (uint16)(i * 8);
        info.entries.push_back(desc);
    }

    return info;
}

DescriptorTableInfo DescriptorTableResolver::parse_idt(ea_t desc_ptr_ea) {
    DescriptorTableInfo info = {};
    info.base_ea = BADADDR;
    info.limit = 0;
    info.entry_count = 0;

    if (!is_loaded(desc_ptr_ea) || !is_loaded(desc_ptr_ea + 5))
        return info;

    info.limit = get_word(desc_ptr_ea);
    info.base_ea = get_dword(desc_ptr_ea + 2);
    info.entry_count = (info.limit + 1) / 8;

    return info;
}

SegmentDescriptor DescriptorTableResolver::resolve_selector(
    const DescriptorTableInfo &gdt, uint16 selector)
{
    int index = (selector >> 3);
    if (index >= 0 && index < (int)gdt.entries.size())
        return gdt.entries[index];

    SegmentDescriptor empty = {};
    empty.selector = selector;
    return empty;
}

void DescriptorTableResolver::annotate(const DescriptorTableInfo &table, bool is_gdt) {
    const char *label = is_gdt ? "GDT" : "IDT";

    msg("[BootEventDetector] %s at 0x%llX, limit=0x%X, %d entries\n",
        label, (unsigned long long)table.base_ea, table.limit, table.entry_count);

    for (const auto &desc : table.entries) {
        if (desc.selector == 0 && desc.base == 0 && desc.limit == 0)
            continue;
        msg("[BootEventDetector]   %s\n", desc.summary().c_str());
    }
}
