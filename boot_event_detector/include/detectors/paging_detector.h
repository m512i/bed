#ifndef BOOT_EVENT_DETECTOR_PAGING_DETECTOR_H
#define BOOT_EVENT_DETECTOR_PAGING_DETECTOR_H

#include "detectors/base_detector.h"

class PagingDetector : public BaseDetector {
public:
    bool matches(ea_t ea) override;
    BootEvent *analyze(ea_t ea) override;
    std::string name() const override { return "PagingDetector"; }

private:

    bool has_cr0_pg_nearby(ea_t ea, int range = 20) const;

    bool has_cr4_setup_nearby(ea_t ea, int range = 20) const;
};

#endif
