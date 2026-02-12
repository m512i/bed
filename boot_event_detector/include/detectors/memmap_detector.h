#ifndef BOOT_EVENT_DETECTOR_MEMMAP_DETECTOR_H
#define BOOT_EVENT_DETECTOR_MEMMAP_DETECTOR_H

#include "detectors/base_detector.h"

class MemMapDetector : public BaseDetector {
public:
    bool matches(ea_t ea) override;
    BootEvent *analyze(ea_t ea) override;
    std::string name() const override { return "MemMapDetector"; }

private:

    int get_ax_value(ea_t ea) const;
    bool has_smap_signature(ea_t ea) const;
};

#endif
