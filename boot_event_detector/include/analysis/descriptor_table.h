#ifndef BOOT_EVENT_DETECTOR_DESCRIPTOR_TABLE_H
#define BOOT_EVENT_DETECTOR_DESCRIPTOR_TABLE_H

#include <ida.hpp>
#include <string>
#include <vector>

struct SegmentDescriptor {
    uint16 selector;
    uint32 base;
    uint32 limit;
    uint8  type;
    uint8  dpl;
    bool   present;
    bool   is_code;
    bool   is_data;
    bool   is_system;
    bool   is_64bit;
    bool   default_32;
    bool   granularity;

    std::string decode_type() const;
    std::string summary() const;
};

struct DescriptorTableInfo {
    ea_t   base_ea;
    uint16 limit;
    int    entry_count;
    std::vector<SegmentDescriptor> entries;

    bool valid() const { return base_ea != BADADDR && limit > 0; }
};

class DescriptorTableResolver {
public:
    static DescriptorTableInfo parse_gdt(ea_t desc_ptr_ea);
    static DescriptorTableInfo parse_idt(ea_t desc_ptr_ea);

    static SegmentDescriptor parse_descriptor(ea_t entry_ea);

    static SegmentDescriptor resolve_selector(const DescriptorTableInfo &gdt, uint16 selector);

    static void annotate(const DescriptorTableInfo &table, bool is_gdt);
};

#endif
