#ifndef BOOT_EVENT_DETECTOR_MULTIBOOT_DETECTOR_H
#define BOOT_EVENT_DETECTOR_MULTIBOOT_DETECTOR_H

#include "detectors/base_detector.h"

class MultibootDetector : public BaseDetector {
public:
    bool matches(ea_t ea) override;
    BootEvent *analyze(ea_t ea) override;
    std::string name() const override { return "MultibootDetector"; }

private:
    static const uint32 MB1_MAGIC = 0x1BADB002;
    static const uint32 MB2_MAGIC = 0xE85250D6;
};

#endif
