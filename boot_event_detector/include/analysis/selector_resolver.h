#ifndef BOOT_EVENT_DETECTOR_SELECTOR_RESOLVER_H
#define BOOT_EVENT_DETECTOR_SELECTOR_RESOLVER_H

#include "analysis/descriptor_table.h"
#include "core/event.h"
#include <vector>
#include <map>

struct FarReference {
    ea_t     address;
    uint16   selector;
    ea_t     target_offset;
    bool     is_jump;
    bool     is_call;
    SegmentDescriptor resolved;
    bool     resolved_ok;
};

class SelectorResolver {
public:
    void set_gdt(const DescriptorTableInfo &gdt) { gdt_ = gdt; }

    void scan_far_refs(const std::vector<BootEvent *> &events);

    void enrich_events(std::vector<BootEvent *> &events) const;

    const std::vector<FarReference> &get_refs() const { return refs_; }

private:
    DescriptorTableInfo gdt_;
    std::vector<FarReference> refs_;
};

#endif
