#ifndef BOOT_EVENT_DETECTOR_PE_LOADER_DETECTOR_H
#define BOOT_EVENT_DETECTOR_PE_LOADER_DETECTOR_H

#include "detectors/base_detector.h"

class PeLoaderDetector : public BaseDetector {
public:
    bool matches(ea_t ea) override;
    BootEvent *analyze(ea_t ea) override;
    std::string name() const override { return "PeLoaderDetector"; }

private:
    bool validate_pe(ea_t mz_ea) const;
};

#endif
