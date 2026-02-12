#ifndef BOOT_EVENT_DETECTOR_PMODE_DETECTOR_H
#define BOOT_EVENT_DETECTOR_PMODE_DETECTOR_H

#include "detectors/base_detector.h"

class PmodeDetector : public BaseDetector {
public:
    bool matches(ea_t ea) override;
    BootEvent *analyze(ea_t ea) override;
    std::string name() const override { return "PmodeDetector"; }

private:

    bool has_far_jump_ahead(ea_t ea, int lookahead = 10) const;
};

#endif
