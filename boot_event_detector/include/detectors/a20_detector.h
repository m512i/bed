#ifndef BOOT_EVENT_DETECTOR_A20_DETECTOR_H
#define BOOT_EVENT_DETECTOR_A20_DETECTOR_H

#include "detectors/base_detector.h"

class A20Detector : public BaseDetector {
public:
    bool matches(ea_t ea) override;
    BootEvent *analyze(ea_t ea) override;
    std::string name() const override { return "A20Detector"; }

private:
    enum A20Method {
        A20_FAST_GATE,
        A20_KBD_CTRL,
        A20_BIOS_INT15,
        A20_NONE
    };

    A20Method detect_method(ea_t ea) const;
};

#endif
