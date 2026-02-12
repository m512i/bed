#ifndef BOOT_EVENT_DETECTOR_SCANNER_H
#define BOOT_EVENT_DETECTOR_SCANNER_H

#include "core/event.h"
#include "ui/scan_config.h"
#include "detectors/base_detector.h"
#include <vector>
#include <memory>
#include <set>
#include <map>

class Scanner {
public:
    Scanner();
    ~Scanner();

    void scan_all();

    void set_config(const ScanConfig &cfg) { config_ = cfg; }
    const ScanConfig &get_config() const { return config_; }

    void clear();

    const std::vector<BootEvent *> &get_events() const { return events_; }
    size_t event_count() const { return events_.size(); }

private:
    void register_detectors();
    void add_comment(ea_t ea, const BootEvent *evt);

    void link_sequences();
    void suppress_duplicates();
    void resolve_operands();
    void apply_function_context();

    void cluster_segment_setups();
    void dedup_nearby_events();
    void reclassify_segment_setups();
    void reduce_uefi_noise();
    void run_semantic_analysis();

    void scan_segment_flow(segment_t *seg);
    void scan_from(ea_t start, ea_t seg_end, std::set<ea_t> &visited);

    int next_sequence_id_;
    ScanConfig config_;

    std::vector<std::unique_ptr<BaseDetector>> detectors_;
    std::vector<BootEvent *> events_;
};

#endif
