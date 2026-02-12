#ifndef BOOT_EVENT_DETECTOR_MODE_TIMELINE_H
#define BOOT_EVENT_DETECTOR_MODE_TIMELINE_H

#include "analysis/cpu_state.h"
#include "analysis/descriptor_table.h"
#include "core/event.h"
#include <vector>

struct TimelineEntry {
    ea_t        address;
    CpuMode     mode_before;
    CpuMode     mode_after;
    std::string trigger;
    std::string state_summary;
    std::string gdt_info;
};

class ModeTimeline {
public:
    void build(const std::vector<StateSnapshot> &snapshots,
               const std::vector<DescriptorTableInfo> &gdts);

    const std::vector<TimelineEntry> &entries() const { return entries_; }

    void log() const;

    void add_comments() const;

private:
    std::vector<TimelineEntry> entries_;
};

#endif
