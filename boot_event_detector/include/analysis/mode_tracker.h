#ifndef BOOT_EVENT_DETECTOR_MODE_TRACKER_H
#define BOOT_EVENT_DETECTOR_MODE_TRACKER_H

#include "analysis/cpu_state.h"
#include "core/event.h"
#include <vector>
#include <set>
#include <map>

class ModeTracker {
public:
    ModeTracker();

    void run(const std::vector<BootEvent *> &events);

    const std::vector<StateSnapshot> &get_snapshots() const { return snapshots_; }

    const CpuState &get_final_state() const { return state_; }

    void enrich_events(std::vector<BootEvent *> &events) const;

    void validate_paging_sequence(std::vector<BootEvent *> &events) const;

private:
    void process_cr0_write(ea_t ea);
    void process_cr3_write(ea_t ea);
    void process_cr4_write(ea_t ea);
    void process_efer_write(ea_t ea);
    void scan_nearby_cr_writes(ea_t ea, int range);

    uint64 resolve_reg_value(ea_t ea, int reg, int max_back = 30) const;

    void record_snapshot(ea_t ea, CpuMode prev, const std::string &trigger);

    CpuState state_;
    std::vector<StateSnapshot> snapshots_;
};

#endif
