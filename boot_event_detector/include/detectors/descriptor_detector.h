#ifndef BOOT_EVENT_DETECTOR_DESCRIPTOR_DETECTOR_H
#define BOOT_EVENT_DETECTOR_DESCRIPTOR_DETECTOR_H

#include "detectors/base_detector.h"

class DescriptorDetector : public BaseDetector {
public:
    bool matches(ea_t ea) override;
    BootEvent *analyze(ea_t ea) override;
    std::string name() const override { return "DescriptorDetector"; }
};

#endif
