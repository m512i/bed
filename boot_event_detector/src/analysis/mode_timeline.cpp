#include "analysis/mode_timeline.h"
#include <bytes.hpp>
#include <kernwin.hpp>

void ModeTimeline::build(const std::vector<StateSnapshot> &snapshots,
                         const std::vector<DescriptorTableInfo> &gdts)
{
    entries_.clear();

    for (const auto &snap : snapshots) {
        TimelineEntry entry;
        entry.address = snap.address;
        entry.mode_before = snap.prev_mode;
        entry.mode_after = snap.new_mode;
        entry.trigger = snap.trigger;
        entry.state_summary = snap.state.summary();

        for (const auto &gdt : gdts) {
            if (gdt.valid() && gdt.base_ea <= snap.address) {
                char buf[128];
                qsnprintf(buf, sizeof(buf), "GDT@0x%llX (%d entries)",
                    (unsigned long long)gdt.base_ea, gdt.entry_count);
                entry.gdt_info = buf;
            }
        }

        entries_.push_back(entry);
    }
}

void ModeTimeline::log() const {
    if (entries_.empty())
        return;

    msg("[BootEventDetector] === Mode Timeline ===\n");
    for (size_t i = 0; i < entries_.size(); i++) {
        const auto &e = entries_[i];
        msg("[BootEventDetector] [%d] 0x%llX: %s -> %s\n",
            (int)i,
            (unsigned long long)e.address,
            CpuState::mode_to_string(e.mode_before),
            CpuState::mode_to_string(e.mode_after));
        msg("[BootEventDetector]     trigger: %s\n", e.trigger.c_str());
        msg("[BootEventDetector]     state: %s\n", e.state_summary.c_str());
        if (!e.gdt_info.empty())
            msg("[BootEventDetector]     %s\n", e.gdt_info.c_str());
    }
    msg("[BootEventDetector] === End Timeline ===\n");
}

void ModeTimeline::add_comments() const {
    for (size_t i = 0; i < entries_.size(); i++) {
        const auto &e = entries_[i];
        char buf[256];
        qsnprintf(buf, sizeof(buf),
            "[BootEvent] MODE: %s -> %s (%s)",
            CpuState::mode_to_string(e.mode_before),
            CpuState::mode_to_string(e.mode_after),
            e.trigger.c_str());
        set_cmt(e.address, buf, true);
    }
}
