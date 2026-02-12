#ifndef BOOT_EVENT_DETECTOR_STAGE_DETECTOR_H
#define BOOT_EVENT_DETECTOR_STAGE_DETECTOR_H

#include "detectors/base_detector.h"

class StageDetector : public BaseDetector {
public:
    bool matches(ea_t ea) override;
    BootEvent *analyze(ea_t ea) override;
    std::string name() const override { return "StageDetector"; }

private:
    bool is_mbr_signature(ea_t seg_start, ea_t seg_end) const;
    bool is_vbr_signature(ea_t seg_start, ea_t seg_end) const;
    bool is_uefi_entry(ea_t ea) const;
};

#endif
