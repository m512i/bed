#ifndef BOOT_EVENT_DETECTOR_SEGMENT_SETUP_DETECTOR_H
#define BOOT_EVENT_DETECTOR_SEGMENT_SETUP_DETECTOR_H

#include "detectors/base_detector.h"

class SegmentSetupDetector : public BaseDetector {
public:
    bool matches(ea_t ea) override;
    BootEvent *analyze(ea_t ea) override;
    std::string name() const override { return "SegmentSetupDetector"; }

private:

    bool is_stack_setup(ea_t ea) const;

    static const char *seg_reg_name(int reg);
};

#endif
